use sha2::{Digest, Sha256};

use crate::ParseError;

pub const HEADER_SIZE: usize = 256;
pub const MAGIC: &[u8; 8] = b"SYMDATA\0";
pub const VERSION: u32 = 1;
pub const WIDTHS: [usize; 4] = [16, 16, 40, 1];

pub fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut value = [0; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(value)
}

pub fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}

#[cfg(feature = "builder")]
pub fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(feature = "builder")]
pub fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

pub fn align(value: usize) -> Option<usize> {
    value.checked_add(7).map(|value| value & !7)
}

pub fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[derive(Clone, Copy, Debug)]
pub struct Table<'data> {
    pub bytes: &'data [u8],
    pub width: usize,
}

impl<'data> Table<'data> {
    pub fn len(self) -> usize {
        self.bytes.len() / self.width
    }

    pub fn row(self, index: usize) -> &'data [u8] {
        &self.bytes[index * self.width..(index + 1) * self.width]
    }
}

pub fn tables<'data>(
    bytes: &'data [u8],
    limits: [u64; 4],
) -> Result<[Table<'data>; 4], ParseError> {
    let mut result = [Table {
        bytes: &[],
        width: 1,
    }; 4];
    let mut position = HEADER_SIZE;
    for (index, width) in WIDTHS.into_iter().enumerate() {
        let descriptor = 128 + index * 16;
        let offset =
            usize::try_from(read_u64(bytes, descriptor)).map_err(|_| ParseError::Bounds)?;
        let count = read_u64(bytes, descriptor + 8);
        if count > limits[index] {
            return Err(ParseError::Limit("table count"));
        }
        let count = usize::try_from(count).map_err(|_| ParseError::Bounds)?;
        let expected = align(position).ok_or(ParseError::Bounds)?;
        if offset != expected {
            return Err(ParseError::Layout);
        }
        if bytes
            .get(position..offset)
            .ok_or(ParseError::Bounds)?
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(ParseError::Layout);
        }
        let end = count
            .checked_mul(width)
            .and_then(|length| offset.checked_add(length))
            .ok_or(ParseError::Bounds)?;
        result[index] = Table {
            bytes: bytes.get(offset..end).ok_or(ParseError::Bounds)?,
            width,
        };
        position = end;
    }
    if position != bytes.len() {
        return Err(ParseError::Layout);
    }
    Ok(result)
}
