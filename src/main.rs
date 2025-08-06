use crate::invoice::Invoice;

mod bech32;
mod invoice;

pub fn generate_invoice_example() -> Invoice {
    let mut invoice = Invoice::new();
    invoice.amount_msat = Some(25_000_000_000);
    invoice.payment_hash = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
        1, 2,
    ];
    invoice.description = "coffee beans".to_string();
    invoice.features.push(15); // payment_secret
    invoice.features.push(9); // var_onion_optin
    invoice.fallback_addr = vec!["1RustyRX2oai4EYYDpQGWvEL62BBGqN9T".to_string(), "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3".to_string()];
    invoice
}

fn main() {
    println!("BOLT 11 Invoice Forge");
    println!("==================================================================");

    let valid_invoice = generate_invoice_example();
    let valid_encoded = valid_invoice.encode("bc");
    println!("\n1. Valid Invoice:");
    println!("{}", valid_encoded);
}
