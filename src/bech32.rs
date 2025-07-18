use std::fmt;

const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// A 5-bit value (0-31) used in bech32 encoding
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct U5Bits(u8);

impl U5Bits {
    /// Create a new U5Bits value from a u8
    /// Returns None if the value is greater than 31
    pub fn new(value: u8) -> Option<Self> {
        if value <= 31 {
            Some(U5Bits(value))
        } else {
            None
        }
    }

    /// Create a new U5Bits value without bounds checking
    /// # Safety
    /// The caller must ensure that value <= 31
    pub unsafe fn new_unchecked(value: u8) -> Self {
        U5Bits(value)
    }

    /// Get the inner u8 value (guaranteed to be 0-31)
    pub fn value(self) -> u8 {
        self.0
    }

    /// Convert to bech32 character
    pub fn to_char(self) -> char {
        CHARSET[self.0 as usize] as char
    }

    /// Create from bech32 character
    pub fn from_char(c: char) -> Option<Self> {
        CHARSET.iter().position(|&x| x as char == c).map(|i| i as u8).map(U5Bits)
    }
}

impl From<U5Bits> for u8 {
    fn from(u5: U5Bits) -> Self {
        u5.0
    }
}

impl TryFrom<u8> for U5Bits {
    type Error = InvalidU5Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value <= 31 {
            Ok(U5Bits(value))
        } else {
            Err(InvalidU5Error(value))
        }
    }
}

impl fmt::Display for U5Bits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_char())
    }
}

/// Error type for invalid 5-bit values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidU5Error(u8);

impl fmt::Display for InvalidU5Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid 5-bit value: {} (must be 0-31)", self.0)
    }
}

impl std::error::Error for InvalidU5Error {}

// Updated conversion functions to work with U5Bits
pub fn bytes_to_u5_bits(data: &[u8]) -> Vec<U5Bits> {
    let mut result = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;

    for &byte in data {
        acc = (acc << 8) | byte as u32;
        bits += 8;

        while bits >= 5 {
            bits -= 5;
            let value = ((acc >> bits) & 0x1f) as u8;
            result.push(U5Bits(value)); // Safe because we mask to 5 bits
        }
    }

    if bits > 0 {
        let value = ((acc << (5 - bits)) & 0x1f) as u8;
        result.push(U5Bits(value)); // Safe because we mask to 5 bits
    }

    result
}

pub fn u5_bits_to_bytes(data: &[U5Bits]) -> Vec<u8> {
    let mut result = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;

    for &u5_bit in data {
        acc = (acc << 5) | u5_bit.value() as u32;
        bits += 5;

        while bits >= 8 {
            bits -= 8;
            result.push((acc >> bits) as u8);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u5bits_creation() {
        assert_eq!(U5Bits::new(0).unwrap().value(), 0);
        assert_eq!(U5Bits::new(31).unwrap().value(), 31);
        assert!(U5Bits::new(32).is_none());
    }

    #[test]
    fn test_u5bits_char_conversion() {
        let u5 = U5Bits::new(0).unwrap();
        assert_eq!(u5.to_char(), 'q');
        
        let u5_from_char = U5Bits::from_char('q').unwrap();
        assert_eq!(u5_from_char.value(), 0);
    }

    #[test]
    fn test_conversion_roundtrip() {
        let data = b"hello world";
        let u5_bits = bytes_to_u5_bits(data);
        let converted_back = u5_bits_to_bytes(&u5_bits);
        
        // Note: Due to padding, the converted data might have trailing zeros
        assert!(converted_back.starts_with(data));
    }
}