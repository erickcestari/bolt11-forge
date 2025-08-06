pub const CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

pub struct Bech32;

impl Bech32 {
    fn polymod(values: &[u8]) -> u32 {
        let generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
        let mut chk = 1u32;

        for value in values {
            let top = chk >> 25;
            chk = (chk & 0x1ffffff) << 5 ^ (*value as u32);
            for i in 0..5 {
                chk ^= if (top >> i) & 1 != 0 { generator[i] } else { 0 };
            }
        }
        chk
    }

    fn hrp_expand(hrp: &str) -> Vec<u8> {
        let mut result = Vec::new();
        for c in hrp.chars() {
            result.push((c as u8) >> 5);
        }
        result.push(0);
        for c in hrp.chars() {
            result.push((c as u8) & 31);
        }
        result
    }

    fn verify_checksum(hrp: &str, data: &[u8]) -> bool {
        let mut values = Self::hrp_expand(hrp);
        values.extend_from_slice(data);
        Self::polymod(&values) == 1
    }

    fn create_checksum(hrp: &str, data: &[u8]) -> Vec<u8> {
        let mut values = Self::hrp_expand(hrp);
        values.extend_from_slice(data);
        values.extend_from_slice(&[0, 0, 0, 0, 0, 0]);

        let polymod = Self::polymod(&values) ^ 1;
        let mut checksum = Vec::new();
        for i in 0..6 {
            checksum.push(((polymod >> (5 * (5 - i))) & 31) as u8);
        }
        checksum
    }

    pub fn encode(hrp: &str, data: &[u8]) -> String {
        let mut combined = data.to_vec();
        combined.extend_from_slice(&Self::create_checksum(hrp, data));

        let mut result = String::from(hrp);
        result.push('1');
        for d in combined {
            result.push(CHARSET.chars().nth(d as usize).unwrap());
        }
        result
    }

    pub fn decode(bech: &str) -> Result<(String, Vec<u8>), String> {
        if bech.chars().any(|c| (c as u32) < 33 || (c as u32) > 126) {
            return Err("Invalid character".to_string());
        }

        let bech_lower = bech.to_lowercase();
        let bech_upper = bech.to_uppercase();

        if bech != bech_lower && bech != bech_upper {
            return Err("Mixed case".to_string());
        }

        let bech = bech_lower;
        let pos = bech.rfind('1').ok_or("No separator found")?;

        if pos < 1 || pos + 7 > bech.len() {
            return Err("Invalid separator position".to_string());
        }

        let hrp = &bech[..pos];
        let data_part = &bech[pos + 1..];

        if !data_part.chars().all(|c| CHARSET.contains(c)) {
            return Err("Invalid character in data part".to_string());
        }

        let data: Vec<u8> = data_part
            .chars()
            .map(|c| CHARSET.find(c).unwrap() as u8)
            .collect();

        if !Self::verify_checksum(hrp, &data) {
            return Err("Invalid checksum".to_string());
        }

        Ok((hrp.to_string(), data[..data.len() - 6].to_vec()))
    }
}

pub fn convert_bits(data: &[u8], from_bits: u8, to_bits: u8, pad: bool) -> Result<Vec<u8>, String> {
    let mut acc = 0u32;
    let mut bits = 0u8;
    let mut ret = Vec::new();
    let maxv = (1 << to_bits) - 1;
    let max_acc = (1 << (from_bits + to_bits - 1)) - 1;

    for value in data {
        if *value as u32 >= (1 << from_bits) {
            return Err("Invalid input value".to_string());
        }
        acc = ((acc << from_bits) | (*value as u32)) & max_acc;
        bits += from_bits;
        while bits >= to_bits {
            bits -= to_bits;
            ret.push(((acc >> bits) & maxv) as u8);
        }
    }

    if pad {
        if bits > 0 {
            ret.push(((acc << (to_bits - bits)) & maxv) as u8);
        }
    } else if bits >= from_bits || ((acc << (to_bits - bits)) & maxv) != 0 {
        return Err("Invalid padding".to_string());
    }

    Ok(ret)
}
