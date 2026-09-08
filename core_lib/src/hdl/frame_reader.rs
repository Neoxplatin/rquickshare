use std::collections::VecDeque;
use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::{timeout_at, Instant};

const MAX_FRAME_SIZE: usize = 5 * 1024 * 1024;
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const FRAME_TIMEOUT: Duration = Duration::from_secs(60);

/// Owns partial reads so selecting a channel event cannot discard framing bytes.
#[derive(Debug, Default)]
pub(super) struct FrameReader {
    header: [u8; 4],
    header_read: usize,
    body: Vec<u8>,
    body_read: usize,
    deadline: Option<Instant>,
}

impl FrameReader {
    pub(super) async fn read_frame<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> io::Result<Vec<u8>> {
        let mut deadline = *self
            .deadline
            .get_or_insert_with(|| Instant::now() + IDLE_TIMEOUT);
        while self.header_read < self.header.len() {
            let count = timeout_at(deadline, reader.read(&mut self.header[self.header_read..]))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Frame header timed out"))??;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Incomplete frame header",
                ));
            }
            if self.header_read == 0 {
                deadline = Instant::now() + FRAME_TIMEOUT;
                self.deadline = Some(deadline);
            }
            self.header_read += count;
        }
        let length = u32::from_be_bytes(self.header) as usize;
        if length == 0 || length > MAX_FRAME_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid frame length",
            ));
        }
        self.body.resize(length, 0);
        while self.body_read < length {
            let count = timeout_at(deadline, reader.read(&mut self.body[self.body_read..]))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Frame body timed out"))??;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Incomplete frame body",
                ));
            }
            self.body_read += count;
        }
        let frame = std::mem::take(&mut self.body);
        self.header_read = 0;
        self.body_read = 0;
        self.deadline = None;
        Ok(frame)
    }
}

/// A cancelled write is terminal: callers must close the connection rather than
/// retrying a partially written frame.
pub(super) async fn write_frame<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    bytes: &[u8],
    receiver: &mut tokio::sync::broadcast::Receiver<crate::channel::ChannelMessage>,
    transfer_id: &str,
) -> io::Result<bool> {
    let mut deferred_commands = VecDeque::new();
    write_frame_with_deferred_commands(writer, bytes, receiver, transfer_id, &mut deferred_commands)
        .await
}

/// Write a frame while preserving non-cancel commands received for the same
/// transfer. The caller can process those commands after the write completes.
pub(super) async fn write_frame_with_deferred_commands<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    bytes: &[u8],
    receiver: &mut tokio::sync::broadcast::Receiver<crate::channel::ChannelMessage>,
    transfer_id: &str,
    deferred_commands: &mut VecDeque<crate::channel::ChannelMessage>,
) -> io::Result<bool> {
    use tokio::io::AsyncWriteExt;

    use crate::channel::{ChannelAction, ChannelDirection};

    let deadline = Instant::now() + FRAME_TIMEOUT;
    let mut written = 0;

    while written < bytes.len() {
        tokio::select! {
            result = timeout_at(deadline, writer.write(&bytes[written..])) => {
                let count = result
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Frame write timed out"))??;
                if count == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "Frame write returned zero bytes",
                    ));
                }
                written += count;
            }
            command = receiver.recv() => {
                match command {
                    Ok(message) if message.id == transfer_id
                        && message.direction == ChannelDirection::FrontToLib => {
                        if message.action == Some(ChannelAction::CancelTransfer) {
                            return Ok(true);
                        }
                        deferred_commands.push_back(message);
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                        return Err(io::Error::other(format!(
                            "Control channel lagged by {count} messages"
                        )));
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        return Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "Control channel closed",
                        ));
                    }
                }
            }
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use tokio::io::{duplex, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn preserves_partial_header_and_body_when_cancelled() {
        let (mut tx, mut rx) = duplex(64);
        let mut frames = FrameReader::default();
        tx.write_all(&[0, 0]).await.unwrap();
        tokio::select! {
            biased;
            result = frames.read_frame(&mut rx) => panic!("Unexpected result: {result:?}"),
            _ = std::future::ready(()) => {},
        }
        assert_eq!(frames.header_read, 2);
        tx.write_all(&[0, 3, 10]).await.unwrap();
        tokio::select! {
            biased;
            result = frames.read_frame(&mut rx) => panic!("Unexpected result: {result:?}"),
            _ = std::future::ready(()) => {},
        }
        assert_eq!(frames.body_read, 1);
        tx.write_all(&[20, 30, 0, 0, 0, 1, 40]).await.unwrap();
        assert_eq!(frames.read_frame(&mut rx).await.unwrap(), [10, 20, 30]);
        assert_eq!(frames.read_frame(&mut rx).await.unwrap(), [40]);
    }

    #[tokio::test]
    async fn rejects_invalid_lengths_and_truncated_frames() {
        for length in [0u32, MAX_FRAME_SIZE as u32 + 1] {
            let mut input = &length.to_be_bytes()[..];
            let error = FrameReader::default()
                .read_frame(&mut input)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
        for bytes in [&[0, 0][..], &[0, 0, 0, 2, 1][..]] {
            let mut input = bytes;
            let error = FrameReader::default()
                .read_frame(&mut input)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        }
    }

    #[tokio::test]
    async fn expired_deadline_survives_repeated_calls() {
        let (_tx, mut rx) = duplex(64);
        let mut frames = FrameReader {
            deadline: Some(Instant::now() - Duration::from_secs(1)),
            ..Default::default()
        };
        for _ in 0..2 {
            assert_eq!(
                frames.read_frame(&mut rx).await.unwrap_err().kind(),
                io::ErrorKind::TimedOut
            );
        }
    }
    #[tokio::test]
    async fn cancellation_interrupts_a_stalled_write() {
        use crate::channel::{ChannelAction, ChannelDirection, ChannelMessage};
        let (mut tx, _rx) = duplex(1);
        let (events, mut receiver) = tokio::sync::broadcast::channel(8);
        for id in ["other", "transfer"] {
            events
                .send(ChannelMessage {
                    id: id.into(),
                    direction: ChannelDirection::FrontToLib,
                    action: Some(ChannelAction::CancelTransfer),
                    ..Default::default()
                })
                .unwrap();
        }
        let cancelled = tokio::time::timeout(
            Duration::from_secs(1),
            write_frame(&mut tx, &[1, 2, 3], &mut receiver, "transfer"),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(cancelled);
    }

    #[tokio::test]
    async fn deferred_write_preserves_consent_before_cancel() {
        use crate::channel::{ChannelAction, ChannelDirection, ChannelMessage};

        let (mut tx, _rx) = duplex(1);
        let (commands, mut receiver) = tokio::sync::broadcast::channel(8);
        let mut deferred = VecDeque::new();

        commands
            .send(ChannelMessage {
                id: "transfer".into(),
                direction: ChannelDirection::FrontToLib,
                action: Some(ChannelAction::AcceptTransfer),
                ..Default::default()
            })
            .unwrap();
        commands
            .send(ChannelMessage {
                id: "transfer".into(),
                direction: ChannelDirection::FrontToLib,
                action: Some(ChannelAction::CancelTransfer),
                ..Default::default()
            })
            .unwrap();

        let cancelled = tokio::time::timeout(
            Duration::from_secs(1),
            write_frame_with_deferred_commands(
                &mut tx,
                &[1, 2, 3],
                &mut receiver,
                "transfer",
                &mut deferred,
            ),
        )
        .await
        .unwrap()
        .unwrap();

        assert!(cancelled);
        assert_eq!(deferred.len(), 1);
        assert_eq!(
            deferred.front().and_then(|message| message.action.clone()),
            Some(ChannelAction::AcceptTransfer)
        );
    }

    #[tokio::test]
    async fn progress_flood_does_not_lag_control_receiver() {
        use crate::channel::{ChannelAction, ChannelDirection, ChannelMessage};

        let (progress, _) = tokio::sync::broadcast::channel(1);
        for _ in 0..128 {
            let _ = progress.send(ChannelMessage::default());
        }

        let (commands, mut receiver) = tokio::sync::broadcast::channel(8);
        commands
            .send(ChannelMessage {
                id: "transfer".into(),
                direction: ChannelDirection::FrontToLib,
                action: Some(ChannelAction::CancelTransfer),
                ..Default::default()
            })
            .unwrap();

        let (mut tx, _rx) = duplex(1);
        assert!(write_frame(&mut tx, &[1, 2, 3], &mut receiver, "transfer")
            .await
            .unwrap());
    }
}
