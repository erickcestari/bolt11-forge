use bitcoin::hashes::{Hash, sha256};
use bitcoin::hex::FromHex;
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

use crate::bech32::{U5Bits, bech32_encode};

#[derive(Debug, Clone)]
pub struct TaggedField {
    pub tag: u8,
    pub data: Vec<u8>,
}

impl TaggedField {
    pub fn new(tag: u8, data: Vec<u8>) -> Self {
        Self { tag, data }
    }

    pub fn encode(&self) -> Vec<U5Bits> {
        let mut result = Vec::new();

        // Add tag (5 bits)
        result.push(U5Bits::new(self.tag).unwrap());

        // Calculate data length in 5-bit groups
        let data_u5 = U5Bits::bytes_to_u5_bits(&self.data);
        let length = data_u5.len();

        // Encode length (10 bits = 2 * 5-bit groups)
        result.push(U5Bits::new(((length >> 5) & 0x1f) as u8).unwrap());
        result.push(U5Bits::new((length & 0x1f) as u8).unwrap());

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
    pub features: Vec<u8>,
    pub timestamp: u64,
}

impl Invoice {
    pub fn new() -> Self {
        Self {
            amount_msat: None,
            payment_hash: [0; 32],
            payment_secret: [1; 32],
            description: String::new(),
            expiry: None,
            min_final_cltv_expiry: None,
            features: Vec::new(),
            timestamp: 0,
        }
    }

    // Generate invoice with encoding to bech32
    pub fn encode(&self, network: &str) -> String {
        let mut data = Vec::new();

        // Add timestamp (35 bits = 7 * 5-bit groups)
        let ts_bytes = self.timestamp.to_be_bytes();
        let ts_u5 = U5Bits::bytes_to_u5_bits(&ts_bytes[3..]);
        data.extend_from_slice(&ts_u5[..7]);

        // Payment hash field (tag 'p' = 1)
        let p_field = TaggedField::new(1, self.payment_hash.to_vec());
        data.extend_from_slice(&p_field.encode());

        // Payment secret field (tag 's' = 16)
        let s_field = TaggedField::new(16, self.payment_secret.to_vec());
        data.extend_from_slice(&s_field.encode());

        // Description field (tag 'd' = 13)
        let d_field = TaggedField::new(13, self.description.as_bytes().to_vec());
        data.extend_from_slice(&d_field.encode());

        // Features field (tag '9' = 5) if present
        if !self.features.is_empty() {
            let features_data = self.encode_features();
            let f_field = TaggedField::new(5, features_data);
            data.extend_from_slice(&f_field.encode());
        }

        // Expiry field (tag 'x' = 6) if present
        if let Some(expiry) = self.expiry {
            let expiry_bytes = expiry.to_be_bytes();
            let x_field = TaggedField::new(6, expiry_bytes.to_vec());
            data.extend_from_slice(&x_field.encode());
        }

        // Min final CLTV field (tag 'c' = 24) if present
        if let Some(cltv) = self.min_final_cltv_expiry {
            let cltv_bytes = cltv.to_be_bytes();
            let c_field = TaggedField::new(24, cltv_bytes.to_vec());
            data.extend_from_slice(&c_field.encode());
        }

        // Create HRP (human readable part)
        let amount_str = self.format_amount();
        let hrp = format!("ln{}{}", network, amount_str);

        // Calculate signature
        let signature = self.calculate_signature(&hrp, &data);
        data.extend_from_slice(&signature);

        bech32_encode(&hrp, &data)
    }

    fn format_amount(&self) -> String {
        let amount_msat = match self.amount_msat {
            Some(amt) => amt,
            None => return String::new(),
        };
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

    fn calculate_signature(&self, hrp: &str, data: &[U5Bits]) -> Vec<U5Bits> {
        let private_key_hex = "e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734";
        let private_key_bytes: [u8; 32] = FromHex::from_hex(private_key_hex).expect("Invalid private key hex");

        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&private_key_bytes).expect("Invalid private key");

        // Prepare data for signing
        let mut sign_data = Vec::new();

        // Add HRP as bytes
        sign_data.extend_from_slice(hrp.as_bytes());

        // Convert U5Bits data back to bytes for signing
        let data_bytes = U5Bits::u5_bits_to_bytes(data);
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

        U5Bits::bytes_to_u5_bits(&sig_data)
    }

    fn encode_features(&self) -> Vec<u8> {
        if self.features.is_empty() {
            return Vec::new();
        }

        // Find the highest feature bit
        let max_feature = self.features.iter().max().copied().unwrap_or(0);
        let num_bytes = (max_feature / 8) + 1;
        let mut feature_bytes = vec![0u8; num_bytes as usize];

        // Set feature bits
        for &feature in &self.features {
            let byte_idx = (feature / 8) as usize;
            let bit_idx = feature % 8;
            if byte_idx < feature_bytes.len() {
                feature_bytes[num_bytes as usize - 1 - byte_idx] |= 1 << bit_idx;
            }
        }

        feature_bytes
    }
}
