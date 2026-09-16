mod publisher;

use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "kryptotome")]
#[command(about = "Kryptotome Protocol CLI: Publisher signing toolchain and offline vault runtime", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Ingests data schemas, computes deterministic digests, and signs metadata package
    SignPackage {
        #[arg(short, long)]
        package_id: String,

        #[arg(short, long)]
        title: String,

        #[arg(short, long)]
        version: String,

        #[arg(short = 'n', long)]
        publisher_name: String,

        #[arg(short, long)]
        dir: PathBuf,

        #[arg(short, long)]
        output: PathBuf,

        #[arg(short = 'a', long, default_value = "sha-256")]
        algorithm: String,
    },

    /// Compute deterministic directory digest
    Digest {
        #[arg(short, long)]
        dir: PathBuf,

        #[arg(short = 'a', long, default_value = "sha-256")]
        algorithm: String,
    },

    /// Generate new publisher or vault keypair
    Keygen,

    /// Inspect local vault status
    VaultStatus {
        #[arg(short, long, default_value = ".kryptotome-vault.json")]
        vault_path: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::SignPackage {
            package_id,
            title,
            version,
            publisher_name,
            dir,
            output,
            algorithm,
        } => {
            let digest_algo: kryptotome_core::DigestAlgorithm = algorithm.parse()?;
            println!("Signing package '{}' ({}) from {:?} using {}", title, package_id, dir, digest_algo);
            let mut csprng = OsRng;
            let signing_key = SigningKey::generate(&mut csprng);
            let toolchain = publisher::PublisherToolchain::new(signing_key);

            let manifest = toolchain.build_and_sign_package(
                &package_id,
                &title,
                &version,
                &publisher_name,
                &dir,
                digest_algo,
            )?;

            let json = serde_json::to_string_pretty(&manifest)?;
            std::fs::write(&output, json)?;
            println!("Manifest successfully written to {:?}", output);
            println!("Algorithm: {}", manifest.digest_algorithm);
            println!("Root content digest: {}", manifest.root_digest);
            println!("Indexed files: {}", manifest.files.len());
        }

        Commands::Digest { dir, algorithm } => {
            let digest_algo: kryptotome_core::DigestAlgorithm = algorithm.parse()?;
            let digest = kryptotome_core::compute_directory_digest_with_algorithm(&dir, digest_algo)?;
            println!("Directory: {:?}", dir);
            println!("Algorithm: {}", digest_algo);
            println!("Digest: {}", digest);
        }

        Commands::Keygen => {
            let mut csprng = OsRng;
            let signing_key = SigningKey::generate(&mut csprng);
            let pubkey = signing_key.verifying_key();
            println!("Generated new Kryptotome asymmetric keypair:");
            println!("Public Key: {}", hex::encode(pubkey.as_bytes()));
            println!("Secret Key: {}", hex::encode(&signing_key.to_bytes()));
        }

        Commands::VaultStatus { vault_path } => {
            if vault_path.exists() {
                let vault = kryptotome_vault::VaultStore::load_from_file(&vault_path)?;
                println!("Vault loaded from {:?}", vault_path);
                println!("Stored credentials: {}", vault.credentials.len());
            } else {
                println!("No vault found at {:?}", vault_path);
            }
        }
    }

    Ok(())
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
