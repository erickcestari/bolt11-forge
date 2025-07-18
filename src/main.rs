use std::collections::HashMap;
use bitcoin::secp256k1::{Secp256k1, SecretKey, Message};
use bitcoin::hashes::{Hash, sha256};

mod bech32;
use bech32::{U5Bits, bytes_to_u5_bits, u5_bits_to_bytes};

// Simple bech32 checksum calculation using U5Bits
fn bech32_polymod(values: &[U5Bits]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk = 1u32;
    
    for &value in values {
        let top = chk >> 25;
        chk = (chk & 0x1ffffff) << 5 ^ value.value() as u32;
        for i in 0..5 {
            if (top >> i) & 1 == 1 {
                chk ^= GEN[i];
            }
        }
    }
    chk
}

// Calculate bech32 checksum returning U5Bits
fn bech32_checksum(hrp: &str, data: &[U5Bits]) -> Vec<U5Bits> {
    let mut values = Vec::new();
    
    // Add HRP
    for ch in hrp.chars() {
        values.push(U5Bits::new((ch as u8) >> 5).unwrap());
    }
    values.push(U5Bits::new(0).unwrap());
    for ch in hrp.chars() {
        values.push(U5Bits::new((ch as u8) & 0x1f).unwrap());
    }
    
    // Add data
    values.extend_from_slice(data);
    
    // Add 6 zeros for checksum calculation
    values.extend_from_slice(&[U5Bits::new(0).unwrap(); 6]);
    
    let polymod = bech32_polymod(&values) ^ 1;
    let mut checksum = Vec::new();
    
    for i in 0..6 {
        let value = ((polymod >> (5 * (5 - i))) & 0x1f) as u8;
        checksum.push(U5Bits::new(value).unwrap());
    }
    
    checksum
}

// Encode bech32 string using U5Bits
fn bech32_encode(hrp: &str, data: &[U5Bits]) -> String {
    let checksum = bech32_checksum(hrp, data);
    let mut result = hrp.to_string();
    result.push('1');
    
    for &value in data {
        result.push(value.to_char());
    }
    
    for &value in &checksum {
        result.push(value.to_char());
    }
    
    result
}

#[derive(Debug, Clone)]
pub struct TaggedField {
    pub tag: u8,
    pub data: Vec<u8>,
}

impl TaggedField {
    pub fn new(tag: u8, data: Vec<u8>) -> Self {
        Self { tag, data }
    }
    
    // Encode with optional non-minimal padding, returning U5Bits
    pub fn encode_with_padding(&self, add_padding: bool) -> Vec<U5Bits> {
        let mut result = Vec::new();
        
        // Add tag (5 bits)
        result.push(U5Bits::new(self.tag).unwrap());
        
        // Calculate data length in 5-bit groups
        let data_u5 = bytes_to_u5_bits(&self.data);
        let mut length = data_u5.len();
        
        // Add non-minimal padding if requested
        if add_padding && length > 0 {
            length += 1; // Add one extra 5-bit group of padding
        }
        
        // Encode length (10 bits = 2 * 5-bit groups)
        result.push(U5Bits::new(((length >> 5) & 0x1f) as u8).unwrap());
        result.push(U5Bits::new((length & 0x1f) as u8).unwrap());
        
        // Add padding zeros if requested (non-minimal encoding)
        if add_padding && !data_u5.is_empty() {
            result.push(U5Bits::new(0).unwrap()); // Leading zero 5-bit group
        }
        
        // Add actual data
        result.extend_from_slice(&data_u5);
        
        result
    }
}

#[derive(Debug)]
pub struct Invoice {
    pub amount_msat: Option<u64>,
    pub payment_hash: [u8; 32],
    pub payment_secret: [u8; 32],
    pub description: String,
    pub expiry: Option<u64>,
    pub min_final_cltv_expiry: Option<u16>,
    pub features: HashMap<u8, bool>,
    pub timestamp: u64,
}

impl Invoice {
    pub fn new() -> Self {
        Self {
            amount_msat: None,
            payment_hash: [0; 32],
            payment_secret: [1; 32], // Default test secret
            description: String::new(),
            expiry: None,
            min_final_cltv_expiry: None,
            features: HashMap::new(),
            timestamp: 1496314658, // Test timestamp from BOLT 11 examples
        }
    }
    
    // Generate invoice with option for non-minimal encoding
    pub fn encode(&self, network: &str, non_minimal_features: bool) -> String {
        let mut data = Vec::new();
        
        // Add timestamp (35 bits = 7 * 5-bit groups)
        let ts_bytes = self.timestamp.to_be_bytes();
        let ts_u5 = bytes_to_u5_bits(&ts_bytes[3..]); // Take last 5 bytes for 35 bits
        data.extend_from_slice(&ts_u5[..7]); // Exactly 7 groups for 35 bits
        
        // Payment hash field (tag 'p' = 1)
        let p_field = TaggedField::new(1, self.payment_hash.to_vec());
        data.extend_from_slice(&p_field.encode_with_padding(false));
        
        // Payment secret field (tag 's' = 16)
        let s_field = TaggedField::new(16, self.payment_secret.to_vec());
        data.extend_from_slice(&s_field.encode_with_padding(false));
        
        // Description field (tag 'd' = 13)
        let d_field = TaggedField::new(13, self.description.as_bytes().to_vec());
        data.extend_from_slice(&d_field.encode_with_padding(false));
        
        // Features field (tag '9' = 5) - with optional non-minimal encoding
        if !self.features.is_empty() || non_minimal_features {
            let features_data = self.encode_features();
            let f_field = TaggedField::new(5, features_data);
            data.extend_from_slice(&f_field.encode_with_padding(non_minimal_features));
        }
        
        // Expiry field (tag 'x' = 6) if present
        if let Some(expiry) = self.expiry {
            let expiry_bytes = expiry.to_be_bytes();
            let x_field = TaggedField::new(6, expiry_bytes.to_vec());
            data.extend_from_slice(&x_field.encode_with_padding(false));
        }
        
        // Min final CLTV field (tag 'c' = 24) if present
        if let Some(cltv) = self.min_final_cltv_expiry {
            let cltv_bytes = cltv.to_be_bytes();
            let c_field = TaggedField::new(24, cltv_bytes.to_vec());
            data.extend_from_slice(&c_field.encode_with_padding(false));
        }
        
        // Create HRP (human readable part)
        let amount_str = match self.amount_msat {
            Some(amt) => format_amount(amt),
            None => String::new(),
        };
        let hrp = format!("ln{}{}", network, amount_str);
        
        // Calculate signature over the data
        let signature = self.calculate_signature(&hrp, &data);
        data.extend_from_slice(&signature);
        
        bech32_encode(&hrp, &data)
    }
    
    fn calculate_signature(&self, hrp: &str, data: &[U5Bits]) -> Vec<U5Bits> {
        // Hardcoded private key from BOLT 11 examples
        let private_key_hex = "e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734";
        let private_key_bytes = hex::decode(private_key_hex).expect("Invalid private key hex");
        
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&private_key_bytes).expect("Invalid private key");
        
        // Prepare data for signing
        let mut sign_data = Vec::new();
        
        // Add HRP as bytes
        sign_data.extend_from_slice(hrp.as_bytes());
        
        // Convert U5Bits data back to bytes for signing
        let data_bytes = u5_bits_to_bytes(data);
        sign_data.extend_from_slice(&data_bytes);
        
        // Pad to byte boundary if needed
        while sign_data.len() % 8 != 0 {
            sign_data.push(0);
        }
        
        // Hash the data
        let hash = sha256::Hash::hash(&sign_data);
        let message = Message::from_digest(*hash.as_byte_array());
        
        // Sign the hash
        let signature = secp.sign_ecdsa_recoverable(&message, &secret_key);
        let (recovery_id, sig_bytes) = signature.serialize_compact();
        
        // Convert to U5Bits format for bech32
        let mut sig_data = sig_bytes.to_vec();
        sig_data.push(recovery_id.to_i32() as u8); // Add recovery ID
        
        bytes_to_u5_bits(&sig_data)
    }
    
    fn encode_features(&self) -> Vec<u8> {
        if self.features.is_empty() {
            return Vec::new();
        }
        
        // Find the highest feature bit
        let max_feature = self.features.keys().max().copied().unwrap_or(0);
        let num_bytes = (max_feature / 8) + 1;
        let mut feature_bytes = vec![0u8; num_bytes as usize];
        
        // Set feature bits
        for (&feature, &enabled) in &self.features {
            if enabled {
                let byte_idx = (feature / 8) as usize;
                let bit_idx = feature % 8;
                if byte_idx < feature_bytes.len() {
                    feature_bytes[num_bytes as usize - 1 - byte_idx] |= 1 << bit_idx;
                }
            }
        }
        
        feature_bytes
    }
}

fn format_amount(amount_msat: u64) -> String {
    // Convert millisatoshi to appropriate unit
    if amount_msat % 1000 == 0 {
        let sats = amount_msat / 1000;
        if sats % 1_000_000 == 0 {
            format!("{}m", sats / 1_000_000)
        } else if sats % 1000 == 0 {
            format!("{}u", sats / 1000)
        } else {
            format!("{}n", sats)
        }
    } else {
        format!("{}p", amount_msat)
    }
}

// Test invoice generators
pub fn generate_valid_invoice() -> Invoice {
    let mut invoice = Invoice::new();
    invoice.amount_msat = Some(25_000_000_000); // 25m satoshi
    invoice.payment_hash = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2];
    invoice.description = "coffee beans".to_string();
    invoice.features.insert(8, true);  // basic_mpp
    invoice.features.insert(14, true); // payment_secret
    invoice
}

pub fn generate_empty_features_invoice() -> Invoice {
    let mut invoice = Invoice::new();
    invoice.amount_msat = Some(25_000_000);
    invoice.payment_hash = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2];
    invoice.description = "coffee beans".to_string();
    // No features set, but we'll force include the field with padding
    invoice
}

pub fn generate_non_minimal_features_invoice() -> Invoice {
    let mut invoice = Invoice::new();
    invoice.amount_msat = Some(25_000_000);
    invoice.payment_hash = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2];
    invoice.description = "coffee beans".to_string();
    invoice.features.insert(10, true); // Set one feature bit
    invoice
}

fn main() {
    println!("BOLT 11 Invoice Generator with Non-Minimal Padding (Using U5Bits)");
    println!("==================================================================");
    
    // Generate valid invoice
    let valid_invoice = generate_valid_invoice();
    let valid_encoded = valid_invoice.encode("bc", false);
    println!("\n1. Valid Invoice:");
    println!("{}", valid_encoded);
    
    // Generate invoice with empty features field (should be omitted but we include it)
    let empty_features = generate_empty_features_invoice();
    let empty_encoded = empty_features.encode("bc", true); // Force non-minimal
    println!("\n2. Invalid: Empty features field with padding (should omit field entirely):");
    println!("{}", empty_encoded);
    
    // Generate invoice with non-minimal features encoding
    let non_minimal = generate_non_minimal_features_invoice();
    let non_minimal_encoded = non_minimal.encode("bc", true); // Add padding
    println!("\n3. Invalid: Non-minimal features encoding (leading zero 5-bit group):");
    println!("{}", non_minimal_encoded);
    
    println!("\nTest Vector Analysis:");
    println!("- Valid invoice: Features field properly encoded");
    println!("- Empty features: Includes '9' field with zero length (violates spec)");
    println!("- Non-minimal: Includes leading zero in '9' field data (violates spec)");
    println!("\nThese can be used as test vectors for BOLT 11 compliance testing.");
    println!("\nNote: All invoices use the hardcoded private key from BOLT 11 examples:");
    println!("e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734");

    let mut invoice = Invoice::new();
    invoice.amount_msat = Some(25_000_000);
    invoice.payment_hash = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2];
    invoice.description = "coffee beans".to_string();
    invoice.features.insert(10, true); // Set one feature bit
    invoice.expiry = Some(60); // 1 hour expiry

    println!("\n4. Invoice with expiry:");
    let expiry_encoded = invoice.encode("bc", false);
    println!("{}", expiry_encoded);

    let mut invoice = Invoice::new();
    invoice.amount_msat = Some(25_000_000);
    invoice.payment_hash = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2];
    invoice.description = "coffee beans".to_string();
    invoice.features.insert(10, true); // Set one feature bit
    invoice.min_final_cltv_expiry = Some(18); // 18 block CLTV

    println!("\n5. Invoice with min cltv expiry:");
    let expiry_encoded = invoice.encode("bc", false);
    println!("{}", expiry_encoded);
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_u5bits_conversion() {
        let bytes = vec![0xAB, 0xCD];
        let u5_data = bytes_to_u5_bits(&bytes);
        assert!(!u5_data.is_empty());
        
        // Verify each U5Bits value is valid (this is guaranteed by the type)
        for &value in &u5_data {
            assert!(value.value() < 32);
        }
        
        // Test round-trip conversion
        let bytes_back = u5_bits_to_bytes(&u5_data);
        assert!(bytes_back.starts_with(&bytes));
    }
    
    #[test]
    fn test_tagged_field_encoding() {
        let field = TaggedField::new(1, vec![0x12, 0x34]);
        let encoded = field.encode_with_padding(false);
        let encoded_with_padding = field.encode_with_padding(true);
        
        // With padding should be longer
        assert!(encoded_with_padding.len() > encoded.len());
        
        // All values should be valid U5Bits
        for &u5_bit in &encoded {
            assert!(u5_bit.value() < 32);
        }
    }
    
    #[test]
    fn test_bech32_checksum() {
        let hrp = "lnbc25m";
        let data = vec![U5Bits::new(1).unwrap(), U5Bits::new(2).unwrap()];
        let checksum = bech32_checksum(hrp, &data);
        
        // Checksum should be exactly 6 U5Bits values
        assert_eq!(checksum.len(), 6);
        
        // All checksum values should be valid
        for &u5_bit in &checksum {
            assert!(u5_bit.value() < 32);
        }
    }
    
    #[test]
    fn test_invoice_generation() {
        let invoice = generate_valid_invoice();
        let encoded = invoice.encode("bc", false);
        
        // Should start with lnbc (Lightning Bitcoin mainnet)
        assert!(encoded.starts_with("lnbc"));
        
        // Should contain the amount
        assert!(encoded.contains("25m"));
        
        // Should be a valid bech32 string (only contains valid characters)
        let valid_chars = "qpzry9x8gf2tvdw0s3jn54khce6mua7l1";
        for ch in encoded.chars().skip(4) { // Skip "lnbc" prefix
            if ch != '1' { // Separator is allowed
                assert!(valid_chars.contains(ch), "Invalid character: {}", ch);
            }
        }
    }
    
    #[test]
    fn test_u5bits_polymod() {
        let values = vec![
            U5Bits::new(0).unwrap(),
            U5Bits::new(1).unwrap(),
            U5Bits::new(31).unwrap(),
        ];
        
        let result = bech32_polymod(&values);
        // Just verify it doesn't panic and returns a value
        assert!(result > 0);
    }
}