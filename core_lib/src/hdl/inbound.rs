use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::anyhow;
use bytes::Bytes;
use hmac::{Hmac, Mac};
use libaes::{Cipher, AES_256_KEY_LEN};
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use prost::Message;
use rand::Rng;
use sha2::{Digest, Sha256, Sha512};
use tokio::net::TcpStream;
use tokio::sync::broadcast::{Receiver, Sender};

use super::frame_reader::{write_frame_with_deferred_commands, FrameReader};
use super::inbound_files::{
    choose_destination, cleanup_temp_file, create_temp_file, finalize_temp_file,
    validate_remote_filename,
};
use super::{append_byte_payload_chunk, parse_peer_p256_public_key, InnerState, State};
use crate::channel::{ChannelAction, ChannelDirection, ChannelMessage};
use crate::hdl::info::{InternalFileInfo, TransferMetadata};
use crate::hdl::{TextPayloadInfo, TextPayloadType};
use crate::location_nearby_connections::payload_transfer_frame::{
    payload_header, PacketType, PayloadChunk, PayloadHeader,
};
use crate::location_nearby_connections::{KeepAliveFrame, OfflineFrame, PayloadTransferFrame};
use crate::securegcm::ukey2_alert::AlertType;
use crate::securegcm::{
    ukey2_message, DeviceToDeviceMessage, GcmMetadata, Type, Ukey2Alert, Ukey2ClientFinished,
    Ukey2ClientInit, Ukey2HandshakeCipher, Ukey2Message, Ukey2ServerInit,
};
use crate::securemessage::{
    EcP256PublicKey, EncScheme, GenericPublicKey, Header, HeaderAndBody, PublicKeyType,
    SecureMessage, SigScheme,
};
use crate::sharing_nearby::{paired_key_result_frame, text_metadata};
use crate::utils::{
    encode_point, gen_ecdsa_keypair, gen_random, get_download_dir, hkdf_extract_expand,
    to_four_digit_string, DeviceType, RemoteDeviceInfo,
};
use crate::{location_nearby_connections, sharing_nearby};

type HmacSha256 = Hmac<Sha256>;

const SANITY_DURATION: Duration = Duration::from_micros(10);

#[derive(Debug)]
pub struct InboundRequest {
    socket: TcpStream,
    frame_reader: FrameReader,
    pub state: InnerState,
    temp_file_paths: HashMap<i64, PathBuf>,
    sender: Sender<ChannelMessage>,
    command_receiver: Receiver<ChannelMessage>,
    pending_commands: VecDeque<ChannelMessage>,
}

impl Drop for InboundRequest {
    fn drop(&mut self) {
        // Close handles before removing temporary paths. This also keeps
        // cancellation cleanup working on platforms that do not allow an open
        // file to be unlinked.
        for file in self.state.transferred_files.values_mut() {
            file.file.take();
        }

        for (_, path) in self.temp_file_paths.drain() {
            if let Err(error) = cleanup_temp_file(&path) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    warn!(
                        "Failed to clean up temporary received file {:?}: {}",
                        path, error
                    );
                }
            }
        }
    }
}

impl InboundRequest {
    pub fn new(
        socket: TcpStream,
        id: String,
        sender: Sender<ChannelMessage>,
        command_sender: Sender<ChannelMessage>,
    ) -> Self {
        Self {
            socket,
            frame_reader: FrameReader::default(),
            state: InnerState {
                id,
                server_seq: 0,
                client_seq: 0,
                state: State::Initial,
                encryption_done: true,
                ..Default::default()
            },
            temp_file_paths: HashMap::new(),
            sender,
            command_receiver: command_sender.subscribe(),
            pending_commands: VecDeque::new(),
        }
    }

    pub async fn handle(&mut self) -> Result<(), anyhow::Error> {
        if let Some(command) = self.pending_commands.pop_front() {
            self.handle_command(command).await?;
            return Ok(());
        }

        tokio::select! {
            i = self.command_receiver.recv() => {
                match i {
                    Ok(channel_msg) => {
                        self.handle_command(channel_msg).await?;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                        return Err(anyhow!("Control channel lagged by {count} messages"));
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        return Err(anyhow!(crate::errors::AppError::NotAnError));
                    }
                }
            },
            h = self.frame_reader.read_frame(&mut self.socket) => {
                self._handle(h?).await?
            }
        }

        Ok(())
    }

    async fn handle_command(&mut self, channel_msg: ChannelMessage) -> Result<(), anyhow::Error> {
        if channel_msg.direction == ChannelDirection::LibToFront || channel_msg.id != self.state.id
        {
            return Ok(());
        }

        debug!("inbound: got: {:?}", channel_msg);
        match channel_msg.action {
            Some(ChannelAction::AcceptTransfer) => {
                self.accept_transfer().await?;
            }
            Some(ChannelAction::RejectTransfer) => {
                self.update_state(
                    |e| {
                        e.state = State::Rejected;
                    },
                    true,
                )
                .await;

                self.reject_transfer(Some(
                    sharing_nearby::connection_response_frame::Status::Reject,
                ))
                .await?;
                return Err(anyhow!(crate::errors::AppError::NotAnError));
            }
            Some(ChannelAction::CancelTransfer) => {
                self.update_state(
                    |e| {
                        e.state = State::Cancelled;
                    },
                    true,
                )
                .await;
                return Err(anyhow!(crate::errors::AppError::NotAnError));
            }
            None => {
                trace!("inbound: nothing to do")
            }
        }

        Ok(())
    }

    pub async fn _handle(&mut self, frame_data: Vec<u8>) -> Result<(), anyhow::Error> {
        let current_state = &self.state;
        // Now determine what will be the request type based on current state
        match current_state.state {
            State::Initial => {
                debug!("Handling State::Initial frame");
                let frame = location_nearby_connections::OfflineFrame::decode(&*frame_data)?;
                let rdi = self.process_connection_request(&frame)?;
                info!("RemoteDeviceInfo: {:?}", &rdi);

                // Advance current state
                self.update_state(
                    |e: &mut InnerState| {
                        e.state = State::ReceivedConnectionRequest;
                        e.remote_device_info = Some(rdi);
                    },
                    false,
                )
                .await;
            }
            State::ReceivedConnectionRequest => {
                debug!("Handling State::ReceivedConnectionRequest frame");
                let msg = Ukey2Message::decode(&*frame_data)?;
                self.process_ukey2_client_init(&msg).await?;

                self.update_state(
                    |e: &mut InnerState| {
                        e.state = State::SentUkeyServerInit;
                        e.client_init_msg_data = Some(frame_data);
                    },
                    false,
                )
                .await;
            }
            State::SentUkeyServerInit => {
                debug!("Handling State::SentUkeyServerInit frame");
                let msg = Ukey2Message::decode(&*frame_data)?;
                self.process_ukey2_client_finish(&msg, &frame_data).await?;

                self.update_state(
                    |e: &mut InnerState| {
                        e.state = State::ReceivedUkeyClientFinish;
                    },
                    false,
                )
                .await;
            }
            State::ReceivedUkeyClientFinish => {
                debug!("Handling State::ReceivedUkeyClientFinish frame");
                let frame = location_nearby_connections::OfflineFrame::decode(&*frame_data)?;
                self.process_connection_response(&frame).await?;

                self.update_state(
                    |e: &mut InnerState| {
                        e.state = State::SentConnectionResponse;
                    },
                    false,
                )
                .await;
            }
            _ => {
                debug!("Handling SecureMessage frame");
                let smsg = SecureMessage::decode(&*frame_data)?;
                self.decrypt_and_process_secure_message(&smsg).await?;
            }
        }

        Ok(())
    }

    fn process_connection_request(
        &self,
        frame: &location_nearby_connections::OfflineFrame,
    ) -> Result<RemoteDeviceInfo, anyhow::Error> {
        let v1_frame = frame
            .v1
            .as_ref()
            .ok_or_else(|| anyhow!("Missing required fields"))?;

        if v1_frame.r#type() != location_nearby_connections::v1_frame::FrameType::ConnectionRequest
        {
            return Err(anyhow!(format!(
                "Unexpected frame type: {:?}",
                v1_frame.r#type()
            )));
        }

        let connection_request = v1_frame
            .connection_request
            .as_ref()
            .ok_or_else(|| anyhow!("Missing required fields"))?;

        let endpoint_info = connection_request
            .endpoint_info
            .as_ref()
            .ok_or_else(|| anyhow!("Missing endpoint info"))?;

        // Check if endpoint info length is greater than 17
        if endpoint_info.len() <= 17 {
            return Err(anyhow!("Endpoint info too short"));
        }

        let device_name_length = endpoint_info[17] as usize;
        // Validate length including device name
        if endpoint_info.len() < device_name_length + 18 {
            return Err(anyhow!(
                "Endpoint info too short to contain the device name"
            ));
        }

        // Extract and validate device name based on length
        let device_name = std::str::from_utf8(&endpoint_info[18..(18 + device_name_length)])
            .map_err(|_| anyhow!("Device name is not valid UTF-8"))?;

        // Parsing the device type
        let raw_device_type = (endpoint_info[0] & 7) >> 1_usize;

        Ok(RemoteDeviceInfo {
            name: device_name.to_string(),
            device_type: DeviceType::from_raw_value(raw_device_type),
        })
    }

    async fn process_ukey2_client_init(&mut self, msg: &Ukey2Message) -> Result<(), anyhow::Error> {
        if msg.message_type() != ukey2_message::Type::ClientInit {
            self.send_ukey2_alert(AlertType::BadMessageType).await?;
            return Err(anyhow!(
                "UKey2: message_type({:?}) != ClientInit",
                msg.message_type
            ));
        }

        let client_init = match Ukey2ClientInit::decode(msg.message_data()) {
            Ok(uk2ci) => uk2ci,
            Err(e) => {
                self.send_ukey2_alert(AlertType::BadMessageData).await?;
                return Err(anyhow!("UKey2: Ukey2ClientInit::decode: {}", e));
            }
        };

        if client_init.version() != 1 {
            self.send_ukey2_alert(AlertType::BadVersion).await?;
            return Err(anyhow!("UKey2: client_init.version != 1"));
        }

        if client_init.random().len() != 32 {
            self.send_ukey2_alert(AlertType::BadRandom).await?;
            return Err(anyhow!("UKey2: client_init.random.len != 32"));
        }

        // Searching for preferred cipher commitment
        let mut found = false;
        for commitment in &client_init.cipher_commitments {
            trace!("CipherCommitment: {:?}", commitment.handshake_cipher());
            if Ukey2HandshakeCipher::P256Sha512 == commitment.handshake_cipher() {
                found = true;
                self.update_state(
                    |e| {
                        e.cipher_commitment = Some(commitment.clone());
                    },
                    false,
                )
                .await;
                break;
            }
        }

        if !found {
            self.send_ukey2_alert(AlertType::BadHandshakeCipher).await?;
            return Err(anyhow!("UKey2: badHandshakeCipher"));
        }

        if client_init.next_protocol() != "AES_256_CBC-HMAC_SHA256" {
            self.send_ukey2_alert(AlertType::BadNextProtocol).await?;
            return Err(anyhow!(
                "UKey2: badNextProtocol: {}",
                client_init.next_protocol()
            ));
        }

        let (secret_key, public_key) = gen_ecdsa_keypair();

        let encoded_point = public_key.to_encoded_point(false);
        let x = encoded_point.x().unwrap();
        let y = encoded_point.y().unwrap();

        let pkey = GenericPublicKey {
            r#type: PublicKeyType::EcP256.into(),
            ec_p256_public_key: Some(EcP256PublicKey {
                x: encode_point(Bytes::from(x.to_vec()))?,
                y: encode_point(Bytes::from(y.to_vec()))?,
            }),
            ..Default::default()
        };

        let server_init = Ukey2ServerInit {
            version: Some(1),
            random: Some(rand::rng().random::<[u8; 32]>().to_vec()),
            handshake_cipher: Some(Ukey2HandshakeCipher::P256Sha512.into()),
            public_key: Some(pkey.encode_to_vec()),
        };

        let server_init_msg = Ukey2Message {
            message_type: Some(ukey2_message::Type::ServerInit.into()),
            message_data: Some(server_init.encode_to_vec()),
        };

        let server_init_data = server_init_msg.encode_to_vec();
        self.update_state(
            |e| {
                e.private_key = Some(secret_key);
                e.public_key = Some(public_key);
                e.server_init_data = Some(server_init_data.clone());
            },
            false,
        )
        .await;

        self.send_frame(server_init_data).await?;

        Ok(())
    }

    async fn process_ukey2_client_finish(
        &mut self,
        msg: &Ukey2Message,
        frame_data: &Vec<u8>,
    ) -> Result<(), anyhow::Error> {
        if msg.message_type() != ukey2_message::Type::ClientFinish {
            self.send_ukey2_alert(AlertType::BadMessageType).await?;
            return Err(anyhow!(
                "UKey2: message_type({:?}) != ClientFinish",
                msg.message_type
            ));
        }

        let sha512 = Sha512::digest(frame_data);
        if self.state.cipher_commitment.as_ref().unwrap().commitment() != sha512.as_slice() {
            error!("cipher_commitment isn't equals to sha512(frame_data)");
            return Err(anyhow!("UKey2: cipher_commitment != sha512"));
        }

        let client_finish = match Ukey2ClientFinished::decode(msg.message_data()) {
            Ok(uk2cf) => uk2cf,
            Err(e) => {
                return Err(anyhow!("UKey2: Ukey2ClientFinished::decode: {}", e));
            }
        };

        if client_finish.public_key.is_none() {
            return Err(anyhow!("UKey2: client_finish.public_key None"));
        }

        let client_public_key = match GenericPublicKey::decode(client_finish.public_key()) {
            Ok(cpk) => cpk,
            Err(e) => {
                return Err(anyhow!("UKey2: GenericPublicKey::decode: {}", e));
            }
        };

        self.finalize_key_exchange(client_public_key).await?;

        Ok(())
    }

    async fn process_connection_response(
        &mut self,
        frame: &location_nearby_connections::OfflineFrame,
    ) -> Result<(), anyhow::Error> {
        let v1_frame = frame
            .v1
            .as_ref()
            .ok_or_else(|| anyhow!("Missing required fields"))?;

        if v1_frame.r#type() != location_nearby_connections::v1_frame::FrameType::ConnectionResponse
        {
            return Err(anyhow!(format!(
                "Unexpected frame type: {:?}",
                v1_frame.r#type()
            )));
        }

        let response = location_nearby_connections::OfflineFrame {
			version: Some(location_nearby_connections::offline_frame::Version::V1.into()),
			v1: Some(location_nearby_connections::V1Frame {
				r#type: Some(location_nearby_connections::v1_frame::FrameType::ConnectionResponse.into()),
				connection_response: Some(location_nearby_connections::ConnectionResponseFrame {
					response: Some(location_nearby_connections::connection_response_frame::ResponseStatus::Accept.into()),
					os_info: Some(location_nearby_connections::OsInfo {
						r#type: Some(location_nearby_connections::os_info::OsType::Linux.into())
					}),
					..Default::default()
				}),
				..Default::default()
			})
		};

        self.send_frame(response.encode_to_vec()).await?;

        let paired_encryption = sharing_nearby::Frame {
            version: Some(sharing_nearby::frame::Version::V1.into()),
            v1: Some(sharing_nearby::V1Frame {
                r#type: Some(sharing_nearby::v1_frame::FrameType::PairedKeyEncryption.into()),
                paired_key_encryption: Some(sharing_nearby::PairedKeyEncryptionFrame {
                    secret_id_hash: Some(gen_random(6)),
                    signed_data: Some(gen_random(72)),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };

        self.send_encrypted_frame(&paired_encryption).await?;

        Ok(())
    }

    async fn decrypt_and_process_secure_message(
        &mut self,
        smsg: &SecureMessage,
    ) -> Result<(), anyhow::Error> {
        let mut hmac = HmacSha256::new_from_slice(self.state.recv_hmac_key.as_ref().unwrap())?;
        hmac.update(&smsg.header_and_body);
        if !hmac
            .finalize()
            .into_bytes()
            .as_slice()
            .eq(smsg.signature.as_slice())
        {
            return Err(anyhow!("hmac!=signature"));
        }

        let header_and_body = HeaderAndBody::decode(&*smsg.header_and_body)?;

        let msg_data = header_and_body.body;
        let key = self.state.decrypt_key.as_ref().unwrap();

        let mut cipher = Cipher::new_256(key[..AES_256_KEY_LEN].try_into()?);
        cipher.set_auto_padding(true);
        let decrypted = cipher.cbc_decrypt(header_and_body.header.iv(), &msg_data);

        let d2d_msg = DeviceToDeviceMessage::decode(&*decrypted)?;

        let seq = self.get_client_seq_inc().await;
        if d2d_msg.sequence_number() != seq {
            return Err(anyhow!(
                "Error d2d_msg.sequence_number invalid ({} vs {})",
                d2d_msg.sequence_number(),
                seq
            ));
        }

        let offline = location_nearby_connections::OfflineFrame::decode(d2d_msg.message())?;
        let v1_frame = offline
            .v1
            .as_ref()
            .ok_or_else(|| anyhow!("Missing required fields"))?;
        match v1_frame.r#type() {
            location_nearby_connections::v1_frame::FrameType::PayloadTransfer => {
                trace!("Received FrameType::PayloadTransfer");
                let payload_transfer = v1_frame
                    .payload_transfer
                    .as_ref()
                    .ok_or_else(|| anyhow!("Missing required fields"))?;

                let header = payload_transfer
                    .payload_header
                    .as_ref()
                    .ok_or_else(|| anyhow!("Missing required fields"))?;
                let chunk = payload_transfer
                    .payload_chunk
                    .as_ref()
                    .ok_or_else(|| anyhow!("Missing required fields"))?;

                match header.r#type() {
                    payload_header::PayloadType::Bytes => {
                        info!("Processing PayloadType::Bytes");
                        let payload_id = header.id();

                        let body = chunk.body.as_deref().unwrap_or_default();
                        append_byte_payload_chunk(
                            &mut self.state.payload_buffers,
                            payload_id,
                            header.total_size(),
                            chunk.offset(),
                            body,
                        )?;

                        if (chunk.flags() & 1) == 1 {
                            debug!("Chunk flags & 1 == 1 ?? End of data ??");

                            let buffer = self
                                .state
                                .payload_buffers
                                .remove(&payload_id)
                                .ok_or_else(|| anyhow!("Payload buffer was not created"))?;
                            if !buffer.is_complete() {
                                return Err(anyhow!(
                                    "Payload ended before declared size: {} vs {}",
                                    buffer.data_len(),
                                    buffer.declared_size()
                                ));
                            }
                            let payload_bytes = buffer.into_data();

                            if self.state.text_payload.is_some()
                                && self.state.text_payload.as_ref().unwrap().get_i64_value()
                                    == payload_id
                            {
                                info!("Transfer finished");
                                let end_index = payload_bytes
                                    .iter()
                                    .position(|&b| b == 16)
                                    .unwrap_or(payload_bytes.len());
                                let payload =
                                    std::str::from_utf8(&payload_bytes[..end_index])?.to_owned();

                                match self.state.text_payload.clone().unwrap() {
                                    TextPayloadInfo::Url(_) => {
                                        self.update_state(
                                            |e| {
                                                if let Some(tmd) = e.transfer_metadata.as_mut() {
                                                    tmd.text_payload = Some(payload);
                                                    tmd.text_type = Some(TextPayloadType::Url);
                                                }
                                            },
                                            false,
                                        )
                                        .await;
                                    }
                                    TextPayloadInfo::Text(_) => {
                                        self.update_state(
                                            |e| {
                                                if let Some(tmd) = e.transfer_metadata.as_mut() {
                                                    tmd.text_payload = Some(payload);
                                                    tmd.text_type = Some(TextPayloadType::Text);
                                                }
                                            },
                                            false,
                                        )
                                        .await;
                                    }
                                    TextPayloadInfo::Wifi((_, ssid)) => {
                                        self.update_state(
                                            |e| {
                                                if let Some(tmd) = e.transfer_metadata.as_mut() {
                                                    tmd.text_payload =
                                                        Some(format!("{ssid}: {}", payload.trim()));
                                                    tmd.text_type = Some(TextPayloadType::Wifi);
                                                }
                                            },
                                            false,
                                        )
                                        .await;
                                    }
                                }

                                self.update_state(
                                    |e| {
                                        e.state = State::Finished;
                                    },
                                    true,
                                )
                                .await;
                                self.disconnection().await?;
                                return Err(anyhow!(crate::errors::AppError::NotAnError));
                            } else {
                                let innner_frame =
                                    sharing_nearby::Frame::decode(payload_bytes.as_slice())?;
                                self.process_transfer_setup(&innner_frame).await?;
                            }
                        }
                    }
                    payload_header::PayloadType::File => {
                        info!("Processing PayloadType::File");
                        let payload_id = header.id();
                        let body = chunk.body();
                        let chunk_size = i64::try_from(body.len())
                            .map_err(|_| anyhow!("File chunk is too large"))?;
                        let is_last = (chunk.flags() & 1) == 1;
                        let mut temp_path = if is_last {
                            Some(self.temp_file_paths.get(&payload_id).cloned().ok_or_else(
                                || {
                                    anyhow!(
                                        "Temporary file for payload ID ({payload_id}) is not known"
                                    )
                                },
                            )?)
                        } else {
                            None
                        };
                        let mut completed_file = None;

                        {
                            let file_internal = self
                                .state
                                .transferred_files
                                .get_mut(&payload_id)
                                .ok_or_else(|| {
                                anyhow!("File payload ID ({}) is not known", payload_id)
                            })?;

                            let current_offset = file_internal.bytes_transferred;
                            if current_offset < 0 || file_internal.total_size < 0 {
                                return Err(anyhow!("Invalid file transfer size"));
                            }
                            if chunk.offset() != current_offset {
                                return Err(anyhow!(
                                    "Invalid offset into file {}, expected {}",
                                    chunk.offset(),
                                    current_offset
                                ));
                            }

                            let next_offset = current_offset
                                .checked_add(chunk_size)
                                .ok_or_else(|| anyhow!("File transfer size overflow"))?;
                            if next_offset > file_internal.total_size {
                                return Err(anyhow!(
                                    "Transferred file size exceeds previously specified value: {} vs {}",
                                    next_offset,
                                    file_internal.total_size
                                ));
                            }

                            if !body.is_empty() {
                                file_internal
                                    .file
                                    .as_ref()
                                    .ok_or_else(|| anyhow!("File receive was not accepted"))?
                                    .write_all_at(body, current_offset as u64)?;
                                file_internal.bytes_transferred = next_offset;
                            }

                            if is_last {
                                if file_internal.bytes_transferred != file_internal.total_size {
                                    return Err(anyhow!(
                                        "File payload ended at {} bytes, expected {}",
                                        file_internal.bytes_transferred,
                                        file_internal.total_size
                                    ));
                                }

                                let file = file_internal
                                    .file
                                    .take()
                                    .ok_or_else(|| anyhow!("File receive was not accepted"))?;
                                completed_file = Some((
                                    temp_path
                                        .take()
                                        .expect("temporary path was checked for final chunk"),
                                    file_internal.file_url.clone(),
                                    file,
                                ));
                            }
                        }

                        if !body.is_empty() {
                            self.update_state(
                                |e| {
                                    if let Some(tmd) = e.transfer_metadata.as_mut() {
                                        tmd.ack_bytes += chunk_size as u64;
                                    }
                                },
                                true,
                            )
                            .await;
                        }

                        if let Some((temp_path, final_path, file)) = completed_file {
                            file.sync_all()?;
                            drop(file);
                            let finalized_path = finalize_temp_file(&temp_path, &final_path)?;
                            if finalized_path != final_path {
                                info!(
                                    "Destination appeared during transfer; received file saved as {:?}",
                                    finalized_path
                                );
                            }
                            self.temp_file_paths.remove(&payload_id);
                            self.state.transferred_files.remove(&payload_id);

                            if self.state.transferred_files.is_empty() {
                                info!("Transfer finished");
                                self.update_state(
                                    |e| {
                                        e.state = State::Finished;
                                    },
                                    true,
                                )
                                .await;
                                self.disconnection().await?;
                                return Err(anyhow!(crate::errors::AppError::NotAnError));
                            }
                        }
                    }
                    payload_header::PayloadType::Stream => {
                        error!("Unhandled PayloadType::Stream: {:?}", header.r#type())
                    }
                    payload_header::PayloadType::UnknownPayloadType => {
                        error!(
                            "Invalid PayloadType::UnknownPayloadType: {:?}",
                            header.r#type()
                        )
                    }
                }
            }
            location_nearby_connections::v1_frame::FrameType::KeepAlive => {
                trace!("Sending keepalive");
                self.send_keepalive(true).await?;
            }
            _ => {
                error!("Unhandled offline frame encrypted: {:?}", offline);
            }
        }

        Ok(())
    }

    async fn process_transfer_setup(
        &mut self,
        frame: &sharing_nearby::Frame,
    ) -> Result<(), anyhow::Error> {
        let v1_frame = frame
            .v1
            .as_ref()
            .ok_or_else(|| anyhow!("Missing required fields"))?;

        if v1_frame.r#type() == sharing_nearby::v1_frame::FrameType::Cancel {
            info!("Transfer canceled");
            self.update_state(
                |e| {
                    e.state = State::Cancelled;
                },
                true,
            )
            .await;
            self.disconnection().await?;
            return Err(anyhow!(crate::errors::AppError::NotAnError));
        }

        match self.state.state {
            State::SentConnectionResponse => {
                debug!("Processing State::SentConnectionResponse");
                self.process_paired_key_encryption_frame(v1_frame).await?;
                self.update_state(
                    |e| {
                        e.state = State::SentPairedKeyResult;
                    },
                    false,
                )
                .await;
            }
            State::SentPairedKeyResult => {
                debug!("Processing State::SentPairedKeyResult");
                self.process_paired_key_result(v1_frame).await?;
                self.update_state(
                    |e| {
                        e.state = State::ReceivedPairedKeyResult;
                    },
                    false,
                )
                .await;
            }
            State::ReceivedPairedKeyResult => {
                debug!("Processing State::ReceivedPairedKeyResult");
                self.process_introduction(v1_frame).await?;
            }
            _ => {
                info!(
                    "Unhandled connection state in process_transfer_setup: {:?}",
                    self.state.state
                );
            }
        }

        Ok(())
    }

    async fn process_paired_key_encryption_frame(
        &mut self,
        v1_frame: &sharing_nearby::V1Frame,
    ) -> Result<(), anyhow::Error> {
        if v1_frame.paired_key_encryption.is_none() {
            return Err(anyhow!("Missing required fields"));
        }

        let paired_result = sharing_nearby::Frame {
            version: Some(sharing_nearby::frame::Version::V1.into()),
            v1: Some(sharing_nearby::V1Frame {
                r#type: Some(sharing_nearby::v1_frame::FrameType::PairedKeyResult.into()),
                paired_key_result: Some(sharing_nearby::PairedKeyResultFrame {
                    status: Some(paired_key_result_frame::Status::Unable.into()),
                }),
                ..Default::default()
            }),
        };

        self.send_encrypted_frame(&paired_result).await?;

        Ok(())
    }

    async fn process_paired_key_result(
        &self,
        v1_frame: &sharing_nearby::V1Frame,
    ) -> Result<(), anyhow::Error> {
        if v1_frame.paired_key_result.is_none() {
            return Err(anyhow!("Missing required fields"));
        }

        Ok(())
    }

    async fn process_introduction(
        &mut self,
        v1_frame: &sharing_nearby::V1Frame,
    ) -> Result<(), anyhow::Error> {
        let introduction = v1_frame
            .introduction
            .as_ref()
            .ok_or_else(|| anyhow!("Missing required fields"))?;

        // No need to inform the channel here, we'll do it anyway with files info
        self.update_state(
            |e| {
                e.state = State::WaitingForUserConsent;
            },
            false,
        )
        .await;

        if !introduction.file_metadata.is_empty() && introduction.text_metadata.is_empty() {
            trace!("process_introduction: handling file_metadata");
            let mut files_name = Vec::with_capacity(introduction.file_metadata.len());
            let mut pending_files = Vec::with_capacity(introduction.file_metadata.len());
            let mut seen_payload_ids = HashSet::with_capacity(introduction.file_metadata.len());
            let mut reserved_destinations =
                HashSet::with_capacity(introduction.file_metadata.len());
            let download_dir = get_download_dir();
            let mut total_bytes: u64 = 0;

            for file in &introduction.file_metadata {
                let name = file.name();
                validate_remote_filename(name)?;

                let payload_id = file
                    .payload_id
                    .ok_or_else(|| anyhow!("Missing file payload ID"))?;
                if !seen_payload_ids.insert(payload_id)
                    || self.state.transferred_files.contains_key(&payload_id)
                {
                    return Err(anyhow!("Duplicate file payload ID: {payload_id}"));
                }

                let total_size = file
                    .size
                    .ok_or_else(|| anyhow!("Missing size for file {name:?}"))?;
                if total_size < 0 {
                    return Err(anyhow!(
                        "Invalid negative size for file {name:?}: {total_size}"
                    ));
                }

                let dest = choose_destination(&download_dir, name, &mut reserved_destinations)?;
                info!(
                    "Received file metadata for {:?}, destination: {:?}",
                    name, dest
                );

                total_bytes = total_bytes
                    .checked_add(total_size as u64)
                    .ok_or_else(|| anyhow!("Total transfer size exceeds supported limits"))?;
                pending_files.push(InternalFileInfo {
                    payload_id,
                    file_url: dest,
                    bytes_transferred: 0,
                    total_size,
                    file: None,
                });
                files_name.push(name.to_owned());
            }

            for file in pending_files {
                self.state.transferred_files.insert(file.payload_id, file);
            }

            let metadata = TransferMetadata {
                id: self.state.id.clone(),
                destination: Some(
                    download_dir
                        .into_os_string()
                        .into_string()
                        .map_err(|_| anyhow!("failed to convert PathBuf to String"))?,
                ),
                source: self.state.remote_device_info.clone(),
                files: Some(files_name),
                pin_code: self.state.pin_code.clone(),
                text_description: None,
                total_bytes,
                ..Default::default()
            };

            info!("Asking for user consent: {:?}", metadata);
            self.update_state(
                |e| {
                    e.transfer_metadata = Some(metadata);
                },
                true,
            )
            .await;
        } else if introduction.text_metadata.len() == 1 {
            trace!("process_introduction: handling text_metadata");
            let meta = introduction.text_metadata.first().unwrap();

            match meta.r#type() {
                text_metadata::Type::Url => {
                    let metadata = TransferMetadata {
                        id: self.state.id.clone(),
                        destination: None,
                        source: self.state.remote_device_info.clone(),
                        files: None,
                        pin_code: self.state.pin_code.clone(),
                        text_description: meta.text_title.clone(),
                        ..Default::default()
                    };

                    info!("Asking for user consent: {:?}", metadata);
                    self.update_state(
                        |e| {
                            e.text_payload = Some(TextPayloadInfo::Url(meta.payload_id()));
                            e.transfer_metadata = Some(metadata);
                        },
                        true,
                    )
                    .await;
                }
                text_metadata::Type::PhoneNumber
                | text_metadata::Type::Address
                | text_metadata::Type::Text => {
                    let metadata = TransferMetadata {
                        id: self.state.id.clone(),
                        destination: None,
                        source: self.state.remote_device_info.clone(),
                        files: None,
                        pin_code: self.state.pin_code.clone(),
                        text_description: meta.text_title.clone(),
                        ..Default::default()
                    };

                    info!("Asking for user consent: {:?}", metadata);
                    self.update_state(
                        |e| {
                            e.text_payload = Some(TextPayloadInfo::Text(meta.payload_id()));
                            e.transfer_metadata = Some(metadata);
                        },
                        true,
                    )
                    .await;
                }
                text_metadata::Type::Unknown => {
                    // Reject transfer
                    self.reject_transfer(Some(
						sharing_nearby::connection_response_frame::Status::UnsupportedAttachmentType,
					))
					.await?;
                }
            }
        } else if introduction.wifi_credentials_metadata.len() == 1 {
            trace!("process_introduction: handling wifi_credentials_metadata");
            let meta = introduction.wifi_credentials_metadata.first().unwrap();

            let metadata = TransferMetadata {
                id: self.state.id.clone(),
                destination: None,
                source: self.state.remote_device_info.clone(),
                files: None,
                pin_code: self.state.pin_code.clone(),
                text_description: meta.ssid.clone(),
                ..Default::default()
            };

            self.update_state(
                |e| {
                    e.text_payload = Some(TextPayloadInfo::Wifi((
                        meta.payload_id(),
                        meta.ssid().to_owned(),
                    )));
                    e.transfer_metadata = Some(metadata);
                },
                true,
            )
            .await;
        } else {
            // Reject transfer
            self.reject_transfer(Some(
                sharing_nearby::connection_response_frame::Status::UnsupportedAttachmentType,
            ))
            .await?;
        }

        Ok(())
    }

    async fn disconnection(&mut self) -> Result<(), anyhow::Error> {
        let frame = location_nearby_connections::OfflineFrame {
            version: Some(location_nearby_connections::offline_frame::Version::V1.into()),
            v1: Some(location_nearby_connections::V1Frame {
                r#type: Some(
                    location_nearby_connections::v1_frame::FrameType::Disconnection.into(),
                ),
                disconnection: Some(location_nearby_connections::DisconnectionFrame {
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };

        if self.state.encryption_done {
            self.encrypt_and_send(&frame).await
        } else {
            self.send_frame(frame.encode_to_vec()).await
        }
    }

    async fn accept_transfer(&mut self) -> Result<(), anyhow::Error> {
        let ids: Vec<i64> = self.state.transferred_files.keys().cloned().collect();
        let download_dir = get_download_dir();
        fs::create_dir_all(&download_dir)?;

        for id in ids {
            let mfi = self
                .state
                .transferred_files
                .get(&id)
                .ok_or_else(|| anyhow!("File payload ID ({id}) is not known"))?;
            if mfi.total_size < 0 {
                return Err(anyhow!("Invalid negative size for file payload ID {id}"));
            }
            if mfi.file.is_some() {
                // A repeated accept action must never truncate an in-progress
                // receive. The first action owns the temporary file.
                continue;
            }

            let (temp_path, file) = create_temp_file(&download_dir, id)?;
            let mfi = self
                .state
                .transferred_files
                .get_mut(&id)
                .ok_or_else(|| anyhow!("File payload ID ({id}) is not known"))?;
            mfi.file = Some(file);
            self.temp_file_paths.insert(id, temp_path.clone());
            info!("Created temporary receive file: {:?}", temp_path);
        }

        let frame = sharing_nearby::Frame {
            version: Some(sharing_nearby::frame::Version::V1.into()),
            v1: Some(sharing_nearby::V1Frame {
                r#type: Some(sharing_nearby::v1_frame::FrameType::Response.into()),
                connection_response: Some(sharing_nearby::ConnectionResponseFrame {
                    status: Some(sharing_nearby::connection_response_frame::Status::Accept.into()),
                }),
                ..Default::default()
            }),
        };

        self.send_encrypted_frame(&frame).await?;

        self.update_state(
            |e| {
                e.state = State::ReceivingFiles;
            },
            true,
        )
        .await;

        Ok(())
    }

    async fn reject_transfer(
        &mut self,
        reason: Option<sharing_nearby::connection_response_frame::Status>,
    ) -> Result<(), anyhow::Error> {
        let sreason = if let Some(r) = reason {
            r
        } else {
            sharing_nearby::connection_response_frame::Status::Reject
        };

        let frame = sharing_nearby::Frame {
            version: Some(sharing_nearby::frame::Version::V1.into()),
            v1: Some(sharing_nearby::V1Frame {
                r#type: Some(sharing_nearby::v1_frame::FrameType::Response.into()),
                connection_response: Some(sharing_nearby::ConnectionResponseFrame {
                    status: Some(sreason.into()),
                }),
                ..Default::default()
            }),
        };

        self.send_encrypted_frame(&frame).await?;

        Ok(())
    }

    async fn finalize_key_exchange(
        &mut self,
        raw_peer_key: GenericPublicKey,
    ) -> Result<(), anyhow::Error> {
        let peer_key = parse_peer_p256_public_key(raw_peer_key)?;
        let priv_key = self.state.private_key.as_ref().unwrap();

        let dhs = diffie_hellman(priv_key.to_nonzero_scalar(), peer_key.as_affine());
        let derived_secret = Sha256::digest(dhs.raw_secret_bytes());

        let mut ukey_info: Vec<u8> = vec![];
        ukey_info.extend_from_slice(self.state.client_init_msg_data.as_ref().unwrap());
        ukey_info.extend_from_slice(self.state.server_init_data.as_ref().unwrap());

        let auth_label = "UKEY2 v1 auth".as_bytes();
        let next_label = "UKEY2 v1 next".as_bytes();

        let auth_string = hkdf_extract_expand(auth_label, &derived_secret, &ukey_info, 32)?;
        let next_secret = hkdf_extract_expand(next_label, &derived_secret, &ukey_info, 32)?;

        let salt_hex = "82AA55A0D397F88346CA1CEE8D3909B95F13FA7DEB1D4AB38376B8256DA85510";
        let salt =
            hex::decode(salt_hex).map_err(|e| anyhow!("Failed to decode salt_hex: {}", e))?;

        let d2d_client = hkdf_extract_expand(&salt, &next_secret, "client".as_bytes(), 32)?;
        let d2d_server = hkdf_extract_expand(&salt, &next_secret, "server".as_bytes(), 32)?;

        let key_salt_hex = "BF9D2A53C63616D75DB0A7165B91C1EF73E537F2427405FA23610A4BE657642E";
        let key_salt = hex::decode(key_salt_hex)
            .map_err(|e| anyhow!("Failed to decode key_salt_hex: {}", e))?;

        let client_key = hkdf_extract_expand(&key_salt, &d2d_client, "ENC:2".as_bytes(), 32)?;
        let client_hmac_key = hkdf_extract_expand(&key_salt, &d2d_client, "SIG:1".as_bytes(), 32)?;
        let server_key = hkdf_extract_expand(&key_salt, &d2d_server, "ENC:2".as_bytes(), 32)?;
        let server_hmac_key = hkdf_extract_expand(&key_salt, &d2d_server, "SIG:1".as_bytes(), 32)?;

        self.update_state(
            |e| {
                e.decrypt_key = Some(client_key);
                e.recv_hmac_key = Some(client_hmac_key);
                e.encrypt_key = Some(server_key);
                e.send_hmac_key = Some(server_hmac_key);
                e.pin_code = Some(to_four_digit_string(&auth_string));
                e.encryption_done = true;
            },
            false,
        )
        .await;

        info!("Pin code: {:?}", self.state.pin_code);

        Ok(())
    }

    async fn send_ukey2_alert(&mut self, atype: AlertType) -> Result<(), anyhow::Error> {
        let alert = Ukey2Alert {
            r#type: Some(atype.into()),
            error_message: None,
        };

        let data = Ukey2Message {
            message_type: Some(atype.into()),
            message_data: Some(alert.encode_to_vec()),
        };

        self.send_frame(data.encode_to_vec()).await
    }

    async fn send_encrypted_frame(
        &mut self,
        frame: &sharing_nearby::Frame,
    ) -> Result<(), anyhow::Error> {
        let frame_data = frame.encode_to_vec();
        let body_size = frame_data.len();

        let payload_header = PayloadHeader {
            id: Some(rand::rng().random_range(i64::MIN..i64::MAX)),
            r#type: Some(payload_header::PayloadType::Bytes.into()),
            total_size: Some(body_size as i64),
            is_sensitive: Some(false),
            ..Default::default()
        };

        let transfer = PayloadTransferFrame {
            packet_type: Some(PacketType::Data.into()),
            payload_chunk: Some(PayloadChunk {
                offset: Some(0),
                flags: Some(0),
                body: Some(frame_data),
            }),
            payload_header: Some(payload_header.clone()),
            ..Default::default()
        };

        let wrapper = location_nearby_connections::OfflineFrame {
            version: Some(location_nearby_connections::offline_frame::Version::V1.into()),
            v1: Some(location_nearby_connections::V1Frame {
                r#type: Some(
                    location_nearby_connections::v1_frame::FrameType::PayloadTransfer.into(),
                ),
                payload_transfer: Some(transfer),
                ..Default::default()
            }),
        };

        // Encrypt and send offline
        self.encrypt_and_send(&wrapper).await?;

        // Send lastChunk
        let transfer = PayloadTransferFrame {
            packet_type: Some(PacketType::Data.into()),
            payload_chunk: Some(PayloadChunk {
                offset: Some(body_size as i64),
                flags: Some(1), // lastChunk
                body: Some(vec![]),
            }),
            payload_header: Some(payload_header),
            ..Default::default()
        };

        let wrapper = location_nearby_connections::OfflineFrame {
            version: Some(location_nearby_connections::offline_frame::Version::V1.into()),
            v1: Some(location_nearby_connections::V1Frame {
                r#type: Some(
                    location_nearby_connections::v1_frame::FrameType::PayloadTransfer.into(),
                ),
                payload_transfer: Some(transfer),
                ..Default::default()
            }),
        };

        // Encrypt and send offline
        self.encrypt_and_send(&wrapper).await?;

        Ok(())
    }

    async fn encrypt_and_send(&mut self, frame: &OfflineFrame) -> Result<(), anyhow::Error> {
        let d2d_msg = DeviceToDeviceMessage {
            sequence_number: Some(self.get_server_seq_inc().await),
            message: Some(frame.encode_to_vec()),
        };

        let key = self.state.encrypt_key.as_ref().unwrap();
        let msg_data = d2d_msg.encode_to_vec();
        let iv = gen_random(16);

        let mut cipher = Cipher::new_256(&key[..AES_256_KEY_LEN].try_into().unwrap());
        cipher.set_auto_padding(true);
        let encrypted = cipher.cbc_encrypt(&iv, &msg_data);

        let hb = HeaderAndBody {
            body: encrypted,
            header: Header {
                encryption_scheme: EncScheme::Aes256Cbc.into(),
                signature_scheme: SigScheme::HmacSha256.into(),
                iv: Some(iv),
                public_metadata: Some(
                    GcmMetadata {
                        r#type: Type::DeviceToDeviceMessage.into(),
                        version: Some(1),
                    }
                    .encode_to_vec(),
                ),
                ..Default::default()
            },
        };

        let mut hmac = HmacSha256::new_from_slice(self.state.send_hmac_key.as_ref().unwrap())?;
        hmac.update(&hb.encode_to_vec());
        let result = hmac.finalize();

        let smsg = SecureMessage {
            header_and_body: hb.encode_to_vec(),
            signature: result.into_bytes().to_vec(),
        };

        self.send_frame(smsg.encode_to_vec()).await?;

        Ok(())
    }

    async fn send_keepalive(&mut self, ack: bool) -> Result<(), anyhow::Error> {
        let ack_frame = location_nearby_connections::OfflineFrame {
            version: Some(location_nearby_connections::offline_frame::Version::V1.into()),
            v1: Some(location_nearby_connections::V1Frame {
                r#type: Some(location_nearby_connections::v1_frame::FrameType::KeepAlive.into()),
                keep_alive: Some(KeepAliveFrame { ack: Some(ack) }),
                ..Default::default()
            }),
        };

        if self.state.encryption_done {
            self.encrypt_and_send(&ack_frame).await
        } else {
            self.send_frame(ack_frame.encode_to_vec()).await
        }
    }

    async fn send_frame(&mut self, data: Vec<u8>) -> Result<(), anyhow::Error> {
        let length = data.len();

        // Prepare length prefix in big-endian format
        let length_bytes = [
            (length >> 24) as u8,
            (length >> 16) as u8,
            (length >> 8) as u8,
            length as u8,
        ];

        let mut prefixed_length = Vec::with_capacity(length + 4);
        prefixed_length.extend_from_slice(&length_bytes);
        prefixed_length.extend_from_slice(&data);

        if write_frame_with_deferred_commands(
            &mut self.socket,
            &prefixed_length,
            &mut self.command_receiver,
            &self.state.id,
            &mut self.pending_commands,
        )
        .await?
        {
            self.update_state(|state| state.state = State::Cancelled, true)
                .await;
            return Err(anyhow!(crate::errors::AppError::NotAnError));
        }

        Ok(())
    }

    async fn get_server_seq_inc(&mut self) -> i32 {
        self.update_state(
            |e| {
                e.server_seq += 1;
            },
            false,
        )
        .await;

        self.state.server_seq
    }

    async fn get_client_seq_inc(&mut self) -> i32 {
        self.update_state(
            |e| {
                e.client_seq += 1;
            },
            false,
        )
        .await;

        self.state.client_seq
    }

    async fn update_state<F>(&mut self, f: F, inform: bool)
    where
        F: FnOnce(&mut InnerState),
    {
        f(&mut self.state);

        if !inform {
            return;
        }

        trace!("Sending msg into the channel");
        let _ = self.sender.send(ChannelMessage {
            id: self.state.id.clone(),
            direction: ChannelDirection::LibToFront,
            rtype: Some(crate::channel::TransferType::Inbound),
            state: Some(self.state.state.clone()),
            meta: self.state.transfer_metadata.clone(),
            ..Default::default()
        });
        // Add a small sleep timer to allow the Tokio runtime to have
        // some spare time to process channel's message. Otherwise it
        // get spammed by new requests. Currently set to 10 micro secs.
        tokio::time::sleep(SANITY_DURATION).await;
    }
}
