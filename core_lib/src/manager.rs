use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast::Sender;
use tokio::sync::mpsc::Receiver;
use tokio::sync::{Semaphore, TryAcquireError};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use ts_rs::TS;

use crate::channel::{ChannelDirection, ChannelMessage, TransferType};
use crate::errors::AppError;
use crate::hdl::{InboundRequest, OutboundPayload, OutboundRequest, State};
use crate::utils::RemoteDeviceInfo;

const INNER_NAME: &str = "TcpServer";
const MAX_CONCURRENT_TRANSFERS: usize = 32;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

struct ConnectFailure {
    error: anyhow::Error,
    notify_disconnect: bool,
}

impl ConnectFailure {
    fn initial(error: anyhow::Error) -> Self {
        Self {
            error,
            notify_disconnect: true,
        }
    }

    fn after_handshake(error: anyhow::Error, state: &State) -> Self {
        let is_terminal_state = matches!(state, &State::Finished | &State::Cancelled);
        let is_terminal_error = error.downcast_ref::<AppError>().is_some();

        Self {
            error,
            notify_disconnect: !is_terminal_state && !is_terminal_error,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, TS)]
#[ts(export)]
pub struct SendInfo {
    pub id: String,
    pub name: String,
    pub addr: String,
    pub ob: OutboundPayload,
}

pub struct TcpServer {
    endpoint_id: [u8; 4],
    tcp_listener: TcpListener,
    sender: Sender<ChannelMessage>,
    command_sender: Sender<ChannelMessage>,
    connect_receiver: Receiver<SendInfo>,
}

impl TcpServer {
    pub fn new(
        endpoint_id: [u8; 4],
        tcp_listener: TcpListener,
        sender: Sender<ChannelMessage>,
        command_sender: Sender<ChannelMessage>,
        connect_receiver: Receiver<SendInfo>,
    ) -> Result<Self, anyhow::Error> {
        Ok(Self {
            endpoint_id,
            tcp_listener,
            sender,
            command_sender,
            connect_receiver,
        })
    }

    pub async fn run(&mut self, ctk: CancellationToken) -> Result<(), anyhow::Error> {
        info!("{INNER_NAME}: service starting");

        // A child token lets the manager stop its transfer tasks when the listener
        // exits because of an error or because the send channel was closed, without
        // cancelling the discovery services that share the parent token.
        let transfer_ctk = ctk.child_token();
        let transfer_limit = Arc::new(Semaphore::new(MAX_CONCURRENT_TRANSFERS));
        let mut transfer_tasks = JoinSet::new();
        let mut connect_receiver_open = true;

        loop {
            tokio::select! {
                _ = ctk.cancelled() => {
                    info!("{INNER_NAME}: tracker cancelled, breaking");
                    break;
                }
                task_result = transfer_tasks.join_next(), if !transfer_tasks.is_empty() => {
                    if let Some(Err(e)) = task_result {
                        error!("{INNER_NAME}: transfer task failed: {e}");
                    }
                }
                connect_info = self.connect_receiver.recv(), if connect_receiver_open => {
                    let Some(i) = connect_info else {
                        info!("{INNER_NAME}: connect receiver closed");
                        connect_receiver_open = false;
                        continue;
                    };

                    info!("{INNER_NAME}: connect_receiver: got id={}", i.id);
                    let permit = match Arc::clone(&transfer_limit).try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(TryAcquireError::NoPermits) => {
                            warn!(
                                "{INNER_NAME}: transfer limit reached, rejecting outbound id={}",
                                i.id
                            );
                            let _ = self.sender.send(ChannelMessage {
                                id: i.id,
                                direction: ChannelDirection::LibToFront,
                                rtype: Some(TransferType::Outbound),
                                state: Some(State::Disconnected),
                                ..Default::default()
                            });
                            continue;
                        }
                        Err(TryAcquireError::Closed) => {
                            error!("{INNER_NAME}: transfer limiter closed");
                            break;
                        }
                    };

                    let endpoint_id = self.endpoint_id;
                    let sender = self.sender.clone();
                    let command_sender = self.command_sender.clone();
                    let task_ctk = transfer_ctk.clone();
                    transfer_tasks.spawn(async move {
                        let _permit = permit;
                        let result = tokio::select! {
                            _ = task_ctk.cancelled() => Ok(()),
                            result = Self::connect_with(
                                endpoint_id,
                                sender,
                                command_sender,
                                task_ctk.clone(),
                                i,
                            ) => result,
                        };
                        if let Err(e) = result {
                            error!("{INNER_NAME}: error sending: {e}");
                        }
                    });
                }
                r = self.tcp_listener.accept() => {
                    match r {
                        Ok((socket, remote_addr)) => {
                            trace!("{INNER_NAME}: new client: {remote_addr}");
                            let permit = match Arc::clone(&transfer_limit).try_acquire_owned() {
                                Ok(permit) => permit,
                                Err(TryAcquireError::NoPermits) => {
                                    warn!(
                                        "{INNER_NAME}: transfer limit reached, dropping inbound connection from {remote_addr}"
                                    );
                                    continue;
                                }
                                Err(TryAcquireError::Closed) => {
                                    error!("{INNER_NAME}: transfer limiter closed");
                                    break;
                                }
                            };

                            let esender = self.sender.clone();
                            let csender = self.sender.clone();
                            let command_sender = self.command_sender.clone();
                            let task_ctk = transfer_ctk.clone();
                            let transfer_id = remote_addr.to_string();

                            transfer_tasks.spawn(async move {
                                let _permit = permit;
                                let mut ir = InboundRequest::new(
                                    socket,
                                    remote_addr.to_string(),
                                    csender,
                                    command_sender,
                                );

                                loop {
                                    let result = tokio::select! {
                                        _ = task_ctk.cancelled() => break,
                                        result = ir.handle() => result,
                                    };

                                    match result {
                                        Ok(_) => {},
                                        Err(e) => match e.downcast_ref() {
                                            Some(AppError::NotAnError) => break,
                                            None => {
                                                if ir.state.state == State::Initial {
                                                    break;
                                                }

                                                if !task_ctk.is_cancelled()
                                                    && ir.state.state != State::Finished
                                                {
                                                    let _ = esender.send(ChannelMessage {
                                                        id: transfer_id.clone(),
                                                        direction: ChannelDirection::LibToFront,
                                                        rtype: Some(TransferType::Inbound),
                                                        state: Some(State::Disconnected),
                                                        ..Default::default()
                                                    });
                                                }
                                                error!("{INNER_NAME}: error while handling client: {e} ({:?})", ir.state.state);
                                                break;
                                            }
                                        },
                                    }
                                }
                            });
                        },
                        Err(err) => {
                            error!("{INNER_NAME}: error accepting: {}", err);
                            break;
                        }
                    }
                }
            }
        }

        transfer_ctk.cancel();
        while let Some(task_result) = transfer_tasks.join_next().await {
            if let Err(e) = task_result {
                error!("{INNER_NAME}: transfer task failed during shutdown: {e}");
            }
        }

        Ok(())
    }

    async fn connect_with(
        endpoint_id: [u8; 4],
        sender: Sender<ChannelMessage>,
        command_sender: Sender<ChannelMessage>,
        ctk: CancellationToken,
        si: SendInfo,
    ) -> Result<(), anyhow::Error> {
        let transfer_id = si.id.clone();
        let result =
            Self::connect_inner(endpoint_id, sender.clone(), command_sender, ctk.clone(), si).await;

        // OutboundRequest reports state transitions after the handshake, but a
        // connection can fail before an OutboundRequest exists (DNS, refused
        // connection, or timeout). Report those failures using the original
        // transfer id as well so the frontend can close the right item.
        match result {
            Ok(()) => Ok(()),
            Err(failure) => {
                let is_terminal_error = failure.error.downcast_ref::<AppError>().is_some();
                if failure.notify_disconnect && !ctk.is_cancelled() {
                    let _ = sender.send(ChannelMessage {
                        id: transfer_id,
                        direction: ChannelDirection::LibToFront,
                        rtype: Some(TransferType::Outbound),
                        state: Some(State::Disconnected),
                        ..Default::default()
                    });
                }

                // AppError::NotAnError is the handler's graceful terminal signal
                // (cancel/reject/disconnect), including during either initial
                // handshake write. Do not turn that terminal state into a second
                // Disconnected notification or a task failure.
                if is_terminal_error {
                    Ok(())
                } else {
                    Err(failure.error)
                }
            }
        }
    }

    async fn connect_inner(
        endpoint_id: [u8; 4],
        sender: Sender<ChannelMessage>,
        command_sender: Sender<ChannelMessage>,
        ctk: CancellationToken,
        si: SendInfo,
    ) -> Result<(), ConnectFailure> {
        debug!("{INNER_NAME}: Connecting to: {}", si.addr);
        let socket = tokio::select! {
            _ = ctk.cancelled() => return Ok(()),
            result = tokio::time::timeout(
                CONNECT_TIMEOUT,
                TcpStream::connect(si.addr.as_str()),
            ) => match result {
                Ok(result) => match result {
                    Ok(socket) => socket,
                    Err(error) => return Err(ConnectFailure::initial(error.into())),
                },
                Err(_) => {
                    return Err(ConnectFailure::initial(anyhow::anyhow!(
                        "timed out connecting to {} after {:?}",
                        si.addr,
                        CONNECT_TIMEOUT,
                    )));
                }
            },
        };

        let mut or = OutboundRequest::new(
            endpoint_id,
            socket,
            si.id,
            sender,
            command_sender,
            si.ob,
            RemoteDeviceInfo {
                device_type: crate::DeviceType::Unknown,
                name: si.name,
            },
        );

        // Send connection request
        or.send_connection_request()
            .await
            .map_err(|error| ConnectFailure::after_handshake(error, &or.state.state))?;
        // Send UKEY init
        or.send_ukey2_client_init()
            .await
            .map_err(|error| ConnectFailure::after_handshake(error, &or.state.state))?;

        loop {
            tokio::select! {
                _ = ctk.cancelled() => {
                    info!("{INNER_NAME}: tracker cancelled, breaking");
                    break;
                },
                r = or.handle() => {
                    if let Err(e) = r {
                        match e.downcast_ref() {
                            Some(AppError::NotAnError) => break,
                            None => {
                                return Err(ConnectFailure::after_handshake(
                                    e,
                                    &or.state.state,
                                ));
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use prost::Message;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::{broadcast, mpsc, oneshot};

    use super::*;

    async fn write_prefixed_frame(stream: &mut TcpStream, data: Vec<u8>) {
        let length = u32::try_from(data.len()).expect("test frame fits in a u32");
        stream.write_all(&length.to_be_bytes()).await.unwrap();
        stream.write_all(&data).await.unwrap();
    }

    async fn establish_inbound_handshake(stream: &mut TcpStream) {
        let request = crate::location_nearby_connections::OfflineFrame {
            version: Some(crate::location_nearby_connections::offline_frame::Version::V1.into()),
            v1: Some(crate::location_nearby_connections::V1Frame {
                r#type: Some(
                    crate::location_nearby_connections::v1_frame::FrameType::ConnectionRequest
                        .into(),
                ),
                connection_request: Some(
                    crate::location_nearby_connections::ConnectionRequestFrame {
                        endpoint_info: Some({
                            let mut info = vec![0; 18];
                            info[17] = 0;
                            info
                        }),
                        ..Default::default()
                    },
                ),
                ..Default::default()
            }),
        };
        write_prefixed_frame(stream, request.encode_to_vec()).await;

        let client_init = crate::securegcm::Ukey2Message {
            message_type: Some(crate::securegcm::ukey2_message::Type::ClientInit.into()),
            message_data: Some(
                crate::securegcm::Ukey2ClientInit {
                    version: Some(1),
                    random: Some(vec![0; 32]),
                    cipher_commitments: vec![
                        crate::securegcm::ukey2_client_init::CipherCommitment {
                            handshake_cipher: Some(
                                crate::securegcm::Ukey2HandshakeCipher::P256Sha512.into(),
                            ),
                            commitment: Some(vec![0; 64]),
                        },
                    ],
                    next_protocol: Some("AES_256_CBC-HMAC_SHA256".to_owned()),
                }
                .encode_to_vec(),
            ),
        };
        write_prefixed_frame(stream, client_init.encode_to_vec()).await;

        let mut length = [0; 4];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut length))
            .await
            .unwrap()
            .unwrap();
        let response_len = u32::from_be_bytes(length) as usize;
        assert!(response_len > 0);
        let mut response = vec![0; response_len];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut response))
            .await
            .unwrap()
            .unwrap();
        let response = crate::securegcm::Ukey2Message::decode(response.as_slice()).unwrap();
        assert_eq!(
            response.message_type(),
            crate::securegcm::ukey2_message::Type::ServerInit
        );
    }

    #[test]
    fn cancelled_handshake_does_not_request_disconnect() {
        let failure =
            ConnectFailure::after_handshake(anyhow::anyhow!("write failed"), &State::Cancelled);

        assert!(!failure.notify_disconnect);
    }

    #[tokio::test]
    async fn initial_connect_failure_reports_the_transfer_id() {
        let (sender, mut messages) = broadcast::channel(4);
        let (command_sender, _) = broadcast::channel(4);

        let result = TcpServer::connect_with(
            *b"test",
            sender,
            command_sender,
            CancellationToken::new(),
            SendInfo {
                id: "transfer-id".to_owned(),
                name: "peer".to_owned(),
                // This is rejected while parsing, so the test does not depend
                // on a particular port being unused on the host.
                addr: "[::1".to_owned(),
                ob: OutboundPayload::Files(Vec::new()),
            },
        )
        .await;

        assert!(result.is_err());
        let message = messages.recv().await.unwrap();
        assert_eq!(message.id, "transfer-id");
        assert_eq!(message.direction, ChannelDirection::LibToFront);
        assert_eq!(message.rtype, Some(TransferType::Outbound));
        assert_eq!(message.state, Some(State::Disconnected));
    }

    #[tokio::test]
    async fn stalled_outbound_does_not_block_accept_and_shutdown_closes_both() {
        let stall_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stall_addr = stall_listener.local_addr().unwrap();
        let (stall_ready, stall_ready_rx) = oneshot::channel();
        let stall_task = tokio::spawn(async move {
            let (mut socket, _) = stall_listener.accept().await.unwrap();
            stall_ready.send(()).unwrap();

            // Drain the outbound handshake, then wait for the manager to drop
            // its side during shutdown.
            let mut buffer = [0u8; 4096];
            loop {
                match tokio::time::timeout(Duration::from_secs(2), socket.read(&mut buffer)).await {
                    Ok(Ok(0)) => return true,
                    Ok(Ok(_)) => continue,
                    _ => return false,
                }
            }
        });

        let manager_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let manager_addr = manager_listener.local_addr().unwrap();
        let (messages, _message_receiver) = broadcast::channel(32);
        let (command_sender, _command_receiver) = broadcast::channel(32);
        let command_sender_for_cancel = command_sender.clone();
        let (connect_sender, connect_receiver) = mpsc::channel(4);
        let mut server = TcpServer::new(
            *b"test",
            manager_listener,
            messages,
            command_sender,
            connect_receiver,
        )
        .unwrap();
        let shutdown = CancellationToken::new();
        let server_shutdown = shutdown.clone();
        let server_task = tokio::spawn(async move { server.run(server_shutdown).await });

        connect_sender
            .send(SendInfo {
                id: "stalled-outbound".to_owned(),
                name: "stalled-peer".to_owned(),
                addr: stall_addr.to_string(),
                ob: OutboundPayload::Files(Vec::new()),
            })
            .await
            .unwrap();
        stall_ready_rx.await.unwrap();

        let mut inbound = TcpStream::connect(manager_addr).await.unwrap();
        establish_inbound_handshake(&mut inbound).await;

        let mut cancelled_inbound = TcpStream::connect(manager_addr).await.unwrap();
        establish_inbound_handshake(&mut cancelled_inbound).await;

        command_sender_for_cancel
            .send(ChannelMessage {
                id: cancelled_inbound.local_addr().unwrap().to_string(),
                direction: ChannelDirection::FrontToLib,
                action: Some(crate::channel::ChannelAction::CancelTransfer),
                ..Default::default()
            })
            .unwrap();
        let mut buffer = [0u8; 4096];
        loop {
            let count =
                tokio::time::timeout(Duration::from_secs(2), cancelled_inbound.read(&mut buffer))
                    .await
                    .unwrap()
                    .unwrap();
            if count == 0 {
                break;
            }
        }

        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        loop {
            let count = tokio::time::timeout(Duration::from_secs(2), inbound.read(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            if count == 0 {
                break;
            }
        }
        assert!(stall_task.await.unwrap());
    }
}
