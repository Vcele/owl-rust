// Buffer abstraction layer for packet I/O

use std::fmt;

/// Error type for wire/buffer operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    OutOfBounds,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::OutOfBounds => write!(f, "Out of bounds"),
        }
    }
}

impl std::error::Error for WireError {}

/// Buffer abstraction for safe packet reading and writing.
///
/// Supports a window (start..end) over an underlying byte vector,
/// allowing strip (remove from front) and take (remove from back)
/// operations without copying data.
#[derive(Debug, Clone)]
pub struct Buf {
    data: Vec<u8>,
    start: usize,
    end: usize,
}

impl Buf {
    /// Create a new zeroed owned buffer of `len` bytes
    pub fn new(len: usize) -> Self {
        Buf {
            data: vec![0u8; len],
            start: 0,
            end: len,
        }
    }

    /// Create a buffer from an existing byte vector
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let len = bytes.len();
        Buf {
            data: bytes,
            start: 0,
            end: len,
        }
    }

    /// Create a buffer from a byte slice (copies data)
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self::from_bytes(bytes.to_vec())
    }

    /// Get a reference to the active window of the buffer
    pub fn data(&self) -> &[u8] {
        &self.data[self.start..self.end]
    }

    /// Get a mutable reference to the active window of the buffer
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data[self.start..self.end]
    }

    /// Length of the active window
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Whether the active window is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Strip `len` bytes from the front of the buffer
    pub fn strip(&mut self, len: usize) -> Result<(), WireError> {
        if len > self.len() {
            return Err(WireError::OutOfBounds);
        }
        self.start += len;
        Ok(())
    }

    /// Strip `len` bytes from the end of the buffer
    pub fn take(&mut self, len: usize) -> Result<(), WireError> {
        if len > self.len() {
            return Err(WireError::OutOfBounds);
        }
        self.end -= len;
        Ok(())
    }

    fn check_bounds(&self, offset: usize, size: usize) -> Result<(), WireError> {
        if offset.saturating_add(size) > self.len() {
            Err(WireError::OutOfBounds)
        } else {
            Ok(())
        }
    }

    // --- Read functions ---

    pub fn read_u8(&self, offset: usize) -> Result<u8, WireError> {
        self.check_bounds(offset, 1)?;
        Ok(self.data[self.start + offset])
    }

    pub fn read_le16(&self, offset: usize) -> Result<u16, WireError> {
        self.check_bounds(offset, 2)?;
        let b = &self.data[self.start + offset..];
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn read_be16(&self, offset: usize) -> Result<u16, WireError> {
        self.check_bounds(offset, 2)?;
        let b = &self.data[self.start + offset..];
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn read_le32(&self, offset: usize) -> Result<u32, WireError> {
        self.check_bounds(offset, 4)?;
        let b = &self.data[self.start + offset..];
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn read_be32(&self, offset: usize) -> Result<u32, WireError> {
        self.check_bounds(offset, 4)?;
        let b = &self.data[self.start + offset..];
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read a 6-byte Ethernet MAC address
    pub fn read_ether_addr(&self, offset: usize) -> Result<[u8; 6], WireError> {
        self.check_bounds(offset, 6)?;
        let b = &self.data[self.start + offset..];
        Ok([b[0], b[1], b[2], b[3], b[4], b[5]])
    }

    /// Read a reference to `length` bytes at `offset`
    pub fn read_bytes(&self, offset: usize, length: usize) -> Result<&[u8], WireError> {
        self.check_bounds(offset, length)?;
        Ok(&self.data[self.start + offset..self.start + offset + length])
    }

    /// Read and copy `length` bytes at `offset` into `dest`
    pub fn read_bytes_copy(&self, offset: usize, dest: &mut [u8]) -> Result<(), WireError> {
        let length = dest.len();
        self.check_bounds(offset, length)?;
        dest.copy_from_slice(&self.data[self.start + offset..self.start + offset + length]);
        Ok(())
    }

    /// Read a length-prefixed string (1-byte length prefix)
    pub fn read_int_string(&self, offset: usize, max_len: usize) -> Result<(String, usize), WireError> {
        let raw_len = self.read_u8(offset)? as usize;
        let actual_len = raw_len.min(max_len);
        let bytes = self.read_bytes(offset + 1, actual_len)?;
        let s = String::from_utf8_lossy(bytes).to_string();
        // Return the true wire-format length (raw_len + 1 byte for the length field)
        Ok((s, raw_len + 1))
    }

    /// Read a TLV (Type-Length-Value) entry.
    /// Returns `(type, value_bytes, next_offset)`.
    pub fn read_tlv(&self, offset: usize) -> Result<(u8, &[u8], usize), WireError> {
        let tlv_type = self.read_u8(offset)?;
        let tlv_len = self.read_le16(offset + 1)? as usize;
        let val = self.read_bytes(offset + 3, tlv_len)?;
        Ok((tlv_type, val, offset + 3 + tlv_len))
    }

    // --- Write functions ---

    pub fn write_u8(&mut self, offset: usize, value: u8) -> Result<(), WireError> {
        self.check_bounds(offset, 1)?;
        self.data[self.start + offset] = value;
        Ok(())
    }

    pub fn write_le16(&mut self, offset: usize, value: u16) -> Result<(), WireError> {
        self.check_bounds(offset, 2)?;
        let bytes = value.to_le_bytes();
        self.data[self.start + offset..self.start + offset + 2].copy_from_slice(&bytes);
        Ok(())
    }

    pub fn write_be16(&mut self, offset: usize, value: u16) -> Result<(), WireError> {
        self.check_bounds(offset, 2)?;
        let bytes = value.to_be_bytes();
        self.data[self.start + offset..self.start + offset + 2].copy_from_slice(&bytes);
        Ok(())
    }

    pub fn write_le32(&mut self, offset: usize, value: u32) -> Result<(), WireError> {
        self.check_bounds(offset, 4)?;
        let bytes = value.to_le_bytes();
        self.data[self.start + offset..self.start + offset + 4].copy_from_slice(&bytes);
        Ok(())
    }

    pub fn write_be32(&mut self, offset: usize, value: u32) -> Result<(), WireError> {
        self.check_bounds(offset, 4)?;
        let bytes = value.to_be_bytes();
        self.data[self.start + offset..self.start + offset + 4].copy_from_slice(&bytes);
        Ok(())
    }

    pub fn write_ether_addr(&mut self, offset: usize, addr: &[u8; 6]) -> Result<(), WireError> {
        self.check_bounds(offset, 6)?;
        self.data[self.start + offset..self.start + offset + 6].copy_from_slice(addr);
        Ok(())
    }

    pub fn write_bytes(&mut self, offset: usize, bytes: &[u8]) -> Result<(), WireError> {
        let length = bytes.len();
        self.check_bounds(offset, length)?;
        self.data[self.start + offset..self.start + offset + length].copy_from_slice(bytes);
        Ok(())
    }
}
