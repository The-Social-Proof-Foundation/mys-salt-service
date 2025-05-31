use base64::{Engine as _, engine::general_purpose};
use rand::{RngCore, rngs::OsRng};

fn main() {
    println!("Generating secure master seed...\n");

    // Generate 64 bytes (512 bits) of random data
    let mut seed = vec![0u8; 64];
    OsRng.fill_bytes(&mut seed);

    // Encode to base64
    let encoded = general_purpose::STANDARD.encode(&seed);

    println!("Master Seed (base64):");
    println!("{}", encoded);
    println!("\nSeed length: {} bytes", seed.len());
    println!("\nAdd this to your environment as:");
    println!("MASTER_SEED={}", encoded);
    
    println!("\n⚠️  SECURITY WARNING:");
    println!("- Store this seed securely and never expose it");
    println!("- This seed cannot be recovered if lost");
    println!("- Different seeds will generate different salts");
    println!("- Use different seeds for dev/staging/production");
} 