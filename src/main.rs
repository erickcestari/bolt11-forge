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
    invoice.features.push(8); // basic_mpp
    invoice.features.push(14); // payment_secret
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
