use bitcoin_hashes::sha256;
use regex::Regex;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::bech32::{Bech32, CHARSET, convert_bits};

#[derive(Debug, Clone)]
pub struct InvoiceBolt11 {
    pub currency: String,
    pub amount: Option<f64>,
    pub date: u64,
    pub paymenthash: Vec<u8>,
    pub tags: Vec<(char, Vec<u8>)>,
    pub signature: Option<Vec<u8>>,
    pub pubkey: Option<PublicKey>,
}

impl InvoiceBolt11 {
    pub fn new() -> Self {
        InvoiceBolt11 {
            currency: "bc".to_string(),
            amount: None,
            date: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            paymenthash: Vec::new(),
            tags: Vec::new(),
            signature: None,
            pubkey: None,
        }
    }

    pub fn with_amount(mut self, amount: f64) -> Self {
        self.amount = Some(amount);
        self
    }

    pub fn with_currency(mut self, currency: &str) -> Self {
        self.currency = currency.to_string();
        self
    }

    pub fn with_paymenthash(mut self, hash: Vec<u8>) -> Self {
        self.paymenthash = hash;
        self
    }

    pub fn add_description(mut self, description: &str) -> Self {
        self.tags.push(('d', description.as_bytes().to_vec()));
        self
    }

    pub fn add_description_hash(mut self, hash: Vec<u8>) -> Self {
        self.tags.push(('h', hash));
        self
    }

    pub fn add_expiry(mut self, expiry: u64) -> Self {
        let mut bits = Vec::new();
        let mut exp = expiry;
        while exp > 0 {
            bits.insert(0, (exp & 0x1f) as u8);
            exp >>= 5;
        }
        if bits.is_empty() {
            bits.push(0);
        }
        self.tags.push(('x', bits));
        self
    }
}

pub fn invoice_encode(addr: &InvoiceBolt11, privkey: &str) -> Result<String, String> {
    let mut hrp = "ln".to_string();
    hrp.push_str(&addr.currency);

    if let Some(amount) = addr.amount {
        if (amount * 1e12) % 10.0 != 0.0 {
            return Err("Too many decimal places in amount".to_string());
        }
        hrp.push_str(&shorten_amount(amount));
    }

    let mut data = Vec::new();

    for i in (0..35).rev() {
        data.push(((addr.date >> i) & 1) as u8);
    }

    let mut data_5bit = convert_bits(&data, 1, 5, true)?;

    let p_tag = tagged_field('p', &addr.paymenthash)?;
    data_5bit.extend_from_slice(&p_tag);

    let mut tags_set = HashSet::new();

    for (tag_char, tag_data) in &addr.tags {
        if ['d', 'h', 'n', 'x'].contains(tag_char) {
            if tags_set.contains(tag_char) {
                return Err(format!("Duplicate '{}' tag", tag_char));
            }
        }

        let tag_field = match tag_char {
            'd' => tagged_field('d', tag_data)?,
            'h' => tagged_field('h', tag_data)?,
            'x' => tagged_field('x', tag_data)?,
            _ => return Err(format!("Unknown tag: {}", tag_char)),
        };

        data_5bit.extend_from_slice(&tag_field);
        tags_set.insert(*tag_char);
    }

    if !tags_set.contains(&'d') && !tags_set.contains(&'h') {
        return Err("Must include either 'd' or 'h'".to_string());
    }
    if tags_set.contains(&'d') && tags_set.contains(&'h') {
        return Err("Cannot include both 'd' and 'h'".to_string());
    }

    let secp = Secp256k1::new();
    let privkey = hex::decode(privkey).map_err(|_| "Invalid private key")?;
    let secret_key = SecretKey::from_byte_array(privkey.try_into().unwrap()).unwrap();

    // Prepare message for signing (HRP + data in 5-bit form)
    let mut msg_preimage = hrp.as_bytes().to_vec();
    let data_bytes = convert_bits(&data_5bit, 5, 8, false)?;
    msg_preimage.extend_from_slice(&data_bytes);

    let msg_hash = sha256::Hash::hash(&msg_preimage);
    let msg = Message::from_digest(msg_hash.to_byte_array());

    let sig = secp.sign_ecdsa_recoverable(msg, &secret_key);
    let (recovery_id, sig_data) = sig.serialize_compact();

    let mut sig_with_recovery = sig_data.to_vec();
    sig_with_recovery.push(recovery_id as u8);

    let sig_5bit = convert_bits(&sig_with_recovery, 8, 5, true)?;
    data_5bit.extend_from_slice(&sig_5bit);

    Ok(Bech32::encode(&hrp, &data_5bit))
}

pub fn invoice_decode(invoice: &str) -> Result<InvoiceBolt11, String> {
    let (hrp, data) = Bech32::decode(invoice)?;

    if !hrp.starts_with("ln") {
        return Err("Does not start with 'ln'".to_string());
    }

    if data.len() < 104 {
        return Err("Too short to contain signature".to_string());
    }

    let (data_part, sig_part) = data.split_at(data.len() - 104);

    let mut addr = InvoiceBolt11::new();

    let amount_part = &hrp[2..];
    let re = Regex::new(r"^([a-z]+)(.*)$").unwrap();
    if let Some(caps) = re.captures(amount_part) {
        addr.currency = caps[1].to_string();
        let amount_str = &caps[2];
        if !amount_str.is_empty() {
            addr.amount = Some(unshorten_amount(amount_str)?);
        }
    }

    if data_part.len() < 7 {
        return Err("Data too short for timestamp".to_string());
    }

    let timestamp_5bit = &data_part[0..7];
    let timestamp_bits = convert_bits(timestamp_5bit, 5, 1, false)?;

    addr.date = 0;
    for (i, bit) in timestamp_bits.iter().enumerate() {
        if i >= 35 {
            break;
        }
        addr.date = (addr.date << 1) | (*bit as u64);
    }

    let mut pos = 7;
    while pos < data_part.len() {
        if pos + 3 > data_part.len() {
            break;
        }

        let tag = data_part[pos];
        let len_hi = data_part[pos + 1] as usize;
        let len_lo = data_part[pos + 2] as usize;
        let length = len_hi * 32 + len_lo;
        pos += 3;

        if pos + length > data_part.len() {
            break;
        }

        let tag_data_5bit = &data_part[pos..pos + length];
        pos += length;

        let tag_char = CHARSET.chars().nth(tag as usize).ok_or("Invalid tag")?;

        match tag_char {
            'p' => {
                let tag_data = convert_bits(tag_data_5bit, 5, 8, false)?;
                if tag_data.len() == 32 {
                    addr.paymenthash = tag_data;
                }
            }
            'd' => {
                let tag_data = convert_bits(tag_data_5bit, 5, 8, false)?;
                if let Ok(_) = String::from_utf8(tag_data.clone()) {
                    addr.tags.push(('d', tag_data));
                }
            }
            'h' => {
                let tag_data = convert_bits(tag_data_5bit, 5, 8, false)?;
                if tag_data.len() == 32 {
                    addr.tags.push(('h', tag_data));
                }
            }
            'x' => {
                addr.tags.push(('x', tag_data_5bit.to_vec()));
            }
            _ => {
                // Unknown tag, skip
            }
        }
    }

    let sig_bytes = convert_bits(sig_part, 5, 8, false)?;
    if sig_bytes.len() != 65 {
        return Err("Invalid signature length".to_string());
    }

    let secp = Secp256k1::new();
    let mut msg_preimage = hrp.as_bytes().to_vec();
    let data_bytes = convert_bits(data_part, 5, 8, false)?;
    msg_preimage.extend_from_slice(&data_bytes);

    let msg_hash = sha256::Hash::hash(&msg_preimage);
    let msg = Message::from_digest(msg_hash.to_byte_array());

    let recovery_id = secp256k1::ecdsa::RecoveryId::from_u8_masked(sig_bytes[64]);
    let sig = secp256k1::ecdsa::RecoverableSignature::from_compact(&sig_bytes[..64], recovery_id)
        .unwrap();

    addr.pubkey = Some(secp.recover_ecdsa(msg, &sig).unwrap());
    addr.signature = Some(sig_bytes[..64].to_vec());

    Ok(addr)
}

fn tagged_field(tag: char, data: &[u8]) -> Result<Vec<u8>, String> {
    let tag_val = CHARSET.find(tag).ok_or("Invalid tag character")? as u8;
    let data_5bit = convert_bits(data, 8, 5, true)?;
    let length = data_5bit.len();

    let mut result = vec![tag_val, (length / 32) as u8, (length % 32) as u8];
    result.extend_from_slice(&data_5bit);
    Ok(result)
}

pub fn shorten_amount(amount: f64) -> String {
    let mut amount = (amount * 1e12) as u64;
    let units = ['p', 'n', 'u', 'm', ' '];

    for unit in units {
        if amount % 1000 == 0 && unit != ' ' {
            amount /= 1000;
        } else {
            break;
        }
    }

    if units[units.len() - 1] == ' ' {
        amount.to_string()
    } else {
        format!("{}{}", amount, units[units.len() - 1])
    }
}

pub fn unshorten_amount(amount: &str) -> Result<f64, String> {
    let re = Regex::new(r"^(\d+)([pnum]?)$").unwrap();
    let caps = re.captures(amount).ok_or("Invalid amount format")?;

    let number: f64 = caps[1].parse().map_err(|_| "Invalid number")?;
    let unit = caps.get(2).map(|m| m.as_str()).unwrap_or("");

    match unit {
        "p" => Ok(number / 1e12),
        "n" => Ok(number / 1e9),
        "u" => Ok(number / 1e6),
        "m" => Ok(number / 1e3),
        "" => Ok(number),
        _ => Err("Invalid unit".to_string()),
    }
}
