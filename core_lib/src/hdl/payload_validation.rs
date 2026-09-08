use std::collections::HashMap;

use anyhow::anyhow;
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::{EncodedPoint, PublicKey};

use crate::securemessage::{GenericPublicKey, PublicKeyType};

/// Maximum size of a single BYTES payload.
pub(crate) const MAX_BYTE_PAYLOAD_SIZE: usize = 5 * 1024 * 1024;
/// Bound the memory reserved for all incomplete BYTES payloads on one connection.
pub(crate) const MAX_BUFFERED_BYTE_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;
/// Bound the number of incomplete BYTES payload IDs kept on one connection.
pub(crate) const MAX_BUFFERED_BYTE_PAYLOADS: usize = 64;

#[derive(Debug)]
pub(crate) struct BytePayloadBuffer {
    declared_size: usize,
    data: Vec<u8>,
}

impl BytePayloadBuffer {
    fn new(
        total_size: usize,
        buffers: &HashMap<i64, BytePayloadBuffer>,
    ) -> Result<Self, anyhow::Error> {
        if buffers.len() >= MAX_BUFFERED_BYTE_PAYLOADS {
            return Err(anyhow!(
                "Too many buffered byte payloads (limit: {})",
                MAX_BUFFERED_BYTE_PAYLOADS
            ));
        }
        let buffered_size = buffers.values().try_fold(0usize, |sum, buffer| {
            sum.checked_add(buffer.declared_size)
                .ok_or_else(|| anyhow!("Buffered payload size overflow"))
        })?;
        let aggregate_size = buffered_size
            .checked_add(total_size)
            .ok_or_else(|| anyhow!("Buffered payload size overflow"))?;
        if aggregate_size > MAX_BUFFERED_BYTE_PAYLOAD_SIZE {
            return Err(anyhow!(
                "Buffered byte payloads exceed the {} byte limit",
                MAX_BUFFERED_BYTE_PAYLOAD_SIZE
            ));
        }

        Ok(Self {
            declared_size: total_size,
            data: Vec::with_capacity(total_size),
        })
    }

    pub(crate) fn declared_size(&self) -> usize {
        self.declared_size
    }

    pub(crate) fn data_len(&self) -> usize {
        self.data.len()
    }

    pub(crate) fn append(&mut self, offset: i64, body: &[u8]) -> Result<(), anyhow::Error> {
        let offset = usize::try_from(offset)
            .map_err(|_| anyhow!("Payload chunk offset must be non-negative"))?;
        if offset != self.data.len() {
            return Err(anyhow!(
                "Unexpected chunk offset: {}, expected: {}",
                offset,
                self.data.len()
            ));
        }

        let new_len = self
            .data
            .len()
            .checked_add(body.len())
            .ok_or_else(|| anyhow!("Payload size overflow"))?;
        if new_len > self.declared_size {
            return Err(anyhow!(
                "Payload chunk exceeds declared size: {} vs {}",
                new_len,
                self.declared_size
            ));
        }

        self.data.extend_from_slice(body);
        Ok(())
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.data.len() == self.declared_size
    }

    pub(crate) fn into_data(self) -> Vec<u8> {
        self.data
    }
}

fn validate_total_size(total_size: i64) -> Result<usize, anyhow::Error> {
    let total_size = usize::try_from(total_size)
        .map_err(|_| anyhow!("Payload total size must be non-negative"))?;
    if total_size > MAX_BYTE_PAYLOAD_SIZE {
        return Err(anyhow!(
            "Payload too large: {} bytes (limit: {})",
            total_size,
            MAX_BYTE_PAYLOAD_SIZE
        ));
    }
    Ok(total_size)
}

/// Validate and append one BYTES chunk, removing the partial payload on failure.
pub(crate) fn append_byte_payload_chunk(
    buffers: &mut HashMap<i64, BytePayloadBuffer>,
    payload_id: i64,
    total_size: i64,
    offset: i64,
    body: &[u8],
) -> Result<(), anyhow::Error> {
    let total_size = match validate_total_size(total_size) {
        Ok(total_size) => total_size,
        Err(error) => {
            buffers.remove(&payload_id);
            return Err(error);
        }
    };

    if let Some(buffer) = buffers.get(&payload_id) {
        if buffer.declared_size() != total_size {
            let previous_size = buffer.declared_size();
            buffers.remove(&payload_id);
            return Err(anyhow!(
                "Inconsistent payload size for {}: {} vs {}",
                payload_id,
                total_size,
                previous_size
            ));
        }
    } else {
        let buffer = BytePayloadBuffer::new(total_size, buffers)?;
        buffers.insert(payload_id, buffer);
    }

    let result = buffers
        .get_mut(&payload_id)
        .ok_or_else(|| anyhow!("Payload buffer was not created"))
        .and_then(|buffer| buffer.append(offset, body));
    if result.is_err() {
        buffers.remove(&payload_id);
    }
    result
}

fn normalize_coordinate(name: &str, coordinate: &[u8]) -> Result<[u8; 32], anyhow::Error> {
    // EcP256PublicKey uses big-endian two's-complement integers. A positive
    // value may have one sign-preserving leading zero byte; shorter values
    // are left-padded to the fixed-width SEC1 representation.
    let coordinate = if coordinate.len() == 33 {
        if coordinate[0] != 0 {
            return Err(anyhow!("Invalid peer public key {} coordinate", name));
        }
        &coordinate[1..]
    } else {
        coordinate
    };

    if coordinate.is_empty() || coordinate.len() > 32 {
        return Err(anyhow!(
            "Invalid peer public key {} coordinate length",
            name
        ));
    }

    let mut normalized = [0u8; 32];
    normalized[32 - coordinate.len()..].copy_from_slice(coordinate);
    Ok(normalized)
}

pub(crate) fn parse_peer_p256_public_key(
    raw_peer_key: GenericPublicKey,
) -> Result<PublicKey, anyhow::Error> {
    if raw_peer_key.r#type() != PublicKeyType::EcP256 {
        return Err(anyhow!(
            "Unsupported peer public key type: {:?}",
            raw_peer_key.r#type()
        ));
    }

    let peer_p256_key = raw_peer_key
        .ec_p256_public_key
        .ok_or_else(|| anyhow!("Missing peer P-256 public key"))?;
    let x = normalize_coordinate("x", &peer_p256_key.x)?;
    let y = normalize_coordinate("y", &peer_p256_key.y)?;

    let mut bytes = Vec::with_capacity(65);
    bytes.push(0x04);
    bytes.extend_from_slice(&x);
    bytes.extend_from_slice(&y);

    let encoded_point = EncodedPoint::from_bytes(bytes)
        .map_err(|error| anyhow!("Invalid peer public key encoding: {}", error))?;
    Option::<PublicKey>::from(PublicKey::from_encoded_point(&encoded_point))
        .ok_or_else(|| anyhow!("Invalid peer public key point"))
}

#[cfg(test)]
mod tests {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::SecretKey;

    use super::*;

    #[test]
    fn rejects_negative_total_size() {
        let mut buffers = HashMap::new();
        assert!(append_byte_payload_chunk(&mut buffers, 1, -1, 0, b"x").is_err());
        assert!(buffers.is_empty());
    }

    #[test]
    fn rejects_chunk_that_exceeds_declared_size() {
        let mut buffers = HashMap::new();
        assert!(append_byte_payload_chunk(&mut buffers, 1, 2, 0, b"abc").is_err());
        assert!(buffers.is_empty());
    }

    #[test]
    fn rejects_inconsistent_size_declarations() {
        let mut buffers = HashMap::new();
        append_byte_payload_chunk(&mut buffers, 1, 3, 0, b"a").unwrap();
        assert!(append_byte_payload_chunk(&mut buffers, 1, 4, 1, b"b").is_err());
        assert!(buffers.is_empty());
    }

    #[test]
    fn rejects_excessive_aggregate_reservation() {
        let mut buffers = HashMap::new();
        append_byte_payload_chunk(&mut buffers, 1, MAX_BYTE_PAYLOAD_SIZE as i64, 0, &[]).unwrap();
        append_byte_payload_chunk(&mut buffers, 2, MAX_BYTE_PAYLOAD_SIZE as i64, 0, &[]).unwrap();
        append_byte_payload_chunk(&mut buffers, 3, MAX_BYTE_PAYLOAD_SIZE as i64, 0, &[]).unwrap();
        assert!(
            append_byte_payload_chunk(&mut buffers, 4, (2 * 1024 * 1024) as i64, 0, b"",).is_err()
        );
        assert_eq!(buffers.len(), 3);
    }

    #[test]
    fn rejects_too_many_in_flight_payloads() {
        let mut buffers = HashMap::new();
        for payload_id in 0..MAX_BUFFERED_BYTE_PAYLOADS as i64 {
            append_byte_payload_chunk(&mut buffers, payload_id, 0, 0, b"").unwrap();
        }

        assert!(append_byte_payload_chunk(
            &mut buffers,
            MAX_BUFFERED_BYTE_PAYLOADS as i64,
            0,
            0,
            b""
        )
        .is_err());
        assert_eq!(buffers.len(), MAX_BUFFERED_BYTE_PAYLOADS);
    }

    #[test]
    fn accepts_sign_extended_peer_coordinates() {
        let secret_key = SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let encoded = secret_key.public_key().to_encoded_point(false);
        let key = GenericPublicKey {
            r#type: PublicKeyType::EcP256.into(),
            ec_p256_public_key: Some(crate::securemessage::EcP256PublicKey {
                x: [vec![0], encoded.x().unwrap().to_vec()].concat(),
                y: [vec![0], encoded.y().unwrap().to_vec()].concat(),
            }),
            ..Default::default()
        };

        assert!(parse_peer_p256_public_key(key).is_ok());
    }

    #[test]
    fn rejects_invalid_peer_point() {
        let key = GenericPublicKey {
            r#type: PublicKeyType::EcP256.into(),
            ec_p256_public_key: Some(crate::securemessage::EcP256PublicKey {
                x: vec![0; 32],
                y: vec![0; 32],
            }),
            ..Default::default()
        };

        assert!(parse_peer_p256_public_key(key).is_err());
    }
}
