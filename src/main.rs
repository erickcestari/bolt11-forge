pub mod bech32;
pub mod bolt11;

use clap::{Parser, Subcommand};

use crate::bolt11::{InvoiceBolt11, invoice_decode, invoice_encode};

#[derive(Parser)]
#[command(name = "bolt11-forge")]
#[command(about = "Lightning Network invoice encoder/decoder")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Encode {
        #[arg(long, default_value = "bc")]
        currency: String,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        expires: Option<u64>,
        amount: f64,
        paymenthash: String,
        privkey: String,
    },
    Decode {
        invoice: String,
        #[arg(long)]
        verbose: bool,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encode {
            currency,
            description,
            expires,
            amount,
            paymenthash,
            privkey,
        } => {
            let mut addr = InvoiceBolt11::new()
                .with_currency(&currency)
                .with_amount(amount)
                .with_paymenthash(hex::decode(paymenthash)?);

            if let Some(desc) = description {
                addr = addr.add_description(&desc);
            }

            if let Some(exp) = expires {
                addr = addr.add_expiry(exp);
            }

            let invoice = invoice_encode(&addr, &privkey)?;
            println!("{}", invoice);
        }
        Commands::Decode { invoice, verbose } => {
            let addr = invoice_decode(&invoice)?;

            if let Some(pubkey) = &addr.pubkey {
                println!(
                    "Signed with public key: {}",
                    hex::encode(pubkey.serialize())
                );
            }
            println!("Currency: {}", addr.currency);
            println!("Payment hash: {}", hex::encode(&addr.paymenthash));
            if let Some(amount) = addr.amount {
                println!("Amount: {}", amount);
            }
            println!(
                "Timestamp: {} ({:?})",
                addr.date,
                std::time::UNIX_EPOCH + std::time::Duration::from_secs(addr.date)
            );

            for (tag, data) in &addr.tags {
                match tag {
                    'd' => {
                        if let Ok(desc) = String::from_utf8(data.clone()) {
                            println!("Description: {}", desc);
                        }
                    }
                    'h' => {
                        println!("Description hash: {}", hex::encode(data));
                    }
                    'x' => {
                        // Convert back from 5-bit representation
                        let mut expiry = 0u64;
                        for &byte in data {
                            expiry = (expiry << 5) | (byte as u64);
                        }
                        println!("Expiry (seconds): {}", expiry);
                    }
                    _ => {
                        println!("UNKNOWN TAG {}: {}", tag, hex::encode(data));
                    }
                }
            }

            if verbose {
                if let Some(sig) = &addr.signature {
                    println!("Signature: {}", hex::encode(sig));
                }
            }
        }
    }

    Ok(())
}
