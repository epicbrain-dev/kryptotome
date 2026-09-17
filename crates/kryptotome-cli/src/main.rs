use kryptotome_cli::{batch, bundle, license, publisher, scanner};

use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "kryptotome")]
#[command(version)]
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

        #[arg(
            short = 'l',
            long,
            default_value = "ORC-1.0",
            help = "Open gaming license type: ORC-1.0, CC-BY-4.0, CC0-1.0, Custom-Open"
        )]
        license_type: String,

        #[arg(
            long,
            help = "Custom license URL (defaults to canonical URI for chosen license type)"
        )]
        license_url: Option<String>,

        #[arg(long, help = "License attribution statement / ORC Notice")]
        license_attribution: Option<String>,

        #[arg(
            long,
            default_value_t = false,
            help = "Disable indicatif interactive progress bar"
        )]
        no_progress: bool,
    },

    /// Compute deterministic directory digest
    Digest {
        #[arg(short, long)]
        dir: PathBuf,

        #[arg(short = 'a', long, default_value = "sha-256")]
        algorithm: String,

        #[arg(
            long,
            default_value_t = false,
            help = "Disable indicatif interactive progress bar"
        )]
        no_progress: bool,
    },

    /// Verify cryptographic publisher signature and integrity of a package manifest
    VerifyManifest {
        #[arg(short, long)]
        manifest: PathBuf,

        #[arg(short, long)]
        pubkey: Option<String>,

        #[arg(short, long)]
        dir: Option<PathBuf>,

        #[arg(
            long,
            default_value_t = false,
            help = "Disable indicatif interactive progress bar"
        )]
        no_progress: bool,
    },

    /// Bundle a signed package manifest and compendium directory into a .ktome release archive
    BundlePackage {
        #[arg(short, long)]
        dir: PathBuf,

        #[arg(short, long)]
        output: PathBuf,

        #[arg(
            long,
            help = "Optional existing manifest JSON to bundle instead of creating one"
        )]
        manifest: Option<PathBuf>,

        #[arg(short, long)]
        package_id: Option<String>,

        #[arg(short, long)]
        title: Option<String>,

        #[arg(short, long)]
        version: Option<String>,

        #[arg(short = 'n', long)]
        publisher_name: Option<String>,

        #[arg(short = 'l', long, default_value = "ORC-1.0")]
        license_type: String,

        #[arg(long)]
        license_url: Option<String>,

        #[arg(long)]
        license_attribution: Option<String>,

        #[arg(short = 'a', long, default_value = "sha-256")]
        algorithm: String,

        #[arg(long, default_value_t = false)]
        no_progress: bool,
    },

    /// Unpack a .ktome release archive with optional cryptographic verification
    UnpackPackage {
        #[arg(short, long)]
        bundle: PathBuf,

        #[arg(short, long)]
        output: PathBuf,

        #[arg(
            long,
            default_value_t = false,
            help = "Verify manifest signature and file digests"
        )]
        verify: bool,

        #[arg(long, default_value_t = false)]
        no_progress: bool,
    },

    /// Batch sign and bundle multiple compendium modules into .ktome release packages
    BatchSign {
        #[arg(short, long, help = "Directory containing module subdirectories")]
        source_dir: Option<PathBuf>,

        #[arg(long, help = "Path to batch specification JSON file")]
        spec: Option<PathBuf>,

        #[arg(
            short,
            long,
            help = "Output directory for .ktome archives and release summary"
        )]
        output_dir: PathBuf,

        #[arg(short = 'n', long, default_value = "Open Gaming Publisher")]
        publisher_name: String,

        #[arg(short, long, default_value = "1.0.0")]
        version: String,

        #[arg(short = 'l', long, default_value = "ORC-1.0")]
        license_type: String,

        #[arg(
            short = 'k',
            long,
            help = "Optional 32-byte publisher secret key in hex"
        )]
        secret_key: Option<String>,

        #[arg(long, default_value_t = false)]
        no_progress: bool,
    },

    /// Generate new publisher or vault keypair
    Keygen,

    /// Inspect local vault status
    VaultStatus {
        #[arg(short, long, default_value = ".kryptotome-vault.json")]
        vault_path: PathBuf,
    },

    /// Launch an air-gapped table beacon for zero-Internet convention or tabletop play
    TableBeacon {
        #[arg(short, long, default_value = "session-table-99")]
        session_id: String,

        #[arg(short, long, default_value = "Friday Night Table")]
        table_name: String,

        #[arg(short, long, default_value = "127.0.0.1:8443")]
        bind: String,

        #[arg(short, long, default_value = "paizo/player-core")]
        packages: Vec<String>,
    },

    /// Verify an organized play tournament check-in ticket in < 10ms with zero PII
    TournamentCheckIn {
        #[arg(short, long, help = "Raw ticket QR code string (KRYP:TOURNEY:...)")]
        qr_string: Option<String>,

        #[arg(short, long, help = "Path to ticket JSON file")]
        file: Option<PathBuf>,
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
            license_type,
            license_url,
            license_attribution,
            no_progress,
        } => {
            let digest_algo: kryptotome_core::DigestAlgorithm = algorithm.parse()?;
            let license_enum: kryptotome_cli::license::OpenGameLicenseType =
                license_type.parse()?;
            let url = license_url.unwrap_or_else(|| license_enum.canonical_url().to_string());
            let attribution = license_attribution.unwrap_or_else(|| match license_enum {
                kryptotome_cli::license::OpenGameLicenseType::Cc0_1_0 => "".to_string(),
                _ => format!("Published by {}", publisher_name),
            });

            let license = publisher::PackageLicense {
                r#type: license_enum.as_str().to_string(),
                url,
                attribution,
            };
            license.validate()?;

            println!(
                "Signing package '{}' ({}) from {:?} using {}",
                title, package_id, dir, digest_algo
            );
            println!("License: {} ({})", license.r#type, license.url);
            let mut csprng = OsRng;
            let signing_key = SigningKey::generate(&mut csprng);
            let toolchain = publisher::PublisherToolchain::new(signing_key);

            let scan_options = scanner::ScanOptions {
                algorithm: digest_algo,
                show_progress: !no_progress,
            };

            let manifest = toolchain.build_and_sign_package_with_license(
                &package_id,
                &title,
                &version,
                &publisher_name,
                &dir,
                scan_options,
                license,
            )?;

            let json = serde_json::to_string_pretty(&manifest)?;
            std::fs::write(&output, json)?;
            println!("Manifest successfully written to {:?}", output);
            println!("Algorithm: {}", manifest.digest_algorithm);
            println!("Root content digest: {}", manifest.root_digest);
            println!("Indexed files: {}", manifest.files.len());
            println!(
                "License: {} - {}",
                manifest.license.r#type, manifest.license.attribution
            );
        }

        Commands::Digest {
            dir,
            algorithm,
            no_progress,
        } => {
            let digest_algo: kryptotome_core::DigestAlgorithm = algorithm.parse()?;
            let scan_options = scanner::ScanOptions {
                algorithm: digest_algo,
                show_progress: !no_progress,
            };
            let scanner = scanner::CompendiumScanner::new(scan_options);
            let scan_result = scanner.scan_directory(&dir)?;
            println!("Directory: {:?}", dir);
            println!("Algorithm: {}", digest_algo);
            println!("Digest: {}", scan_result.root_digest);
            println!("Indexed files: {}", scan_result.total_files);
            println!(
                "Total payload: {}",
                indicatif::HumanBytes(scan_result.total_bytes)
            );
        }

        Commands::VerifyManifest {
            manifest,
            pubkey,
            dir,
            no_progress,
        } => {
            println!(
                "Verifying Kryptotome package manifest from {:?}...",
                manifest
            );
            let parsed_manifest = if manifest.extension().is_some_and(|ext| ext == "ktome") {
                println!("Reading embedded manifest.json directly from .ktome archive...");
                bundle::inspect_ktome_archive(&manifest)?
            } else {
                let manifest_content = std::fs::read_to_string(&manifest)?;
                serde_json::from_str::<publisher::PackageManifest>(&manifest_content)?
            };

            let report = publisher::verify_package_manifest(&parsed_manifest, pubkey.as_deref())?;
            println!("✓ Manifest signature verified successfully!");
            println!("  Package: '{}' ({})", report.package_id, report.version);
            println!(
                "  Publisher: {} ({})",
                report.publisher_name, report.publisher_id
            );
            println!(
                "  License: {} (Attribution: '{}') [URL: {}]",
                report.license.r#type, report.license.attribution, report.license.url
            );
            println!("  Algorithm: {}", report.algorithm);
            println!("  Root content digest: {}", report.root_digest);
            println!("  Verifying key: {}", report.verifying_key_hex);
            println!("  Declared files: {}", parsed_manifest.files.len());

            if let Some(compendium_dir) = dir {
                println!(
                    "\nVerifying directory files against manifest from {:?}...",
                    compendium_dir
                );
                let dir_report = publisher::verify_package_directory(
                    &parsed_manifest,
                    &compendium_dir,
                    !no_progress,
                )?;
                if dir_report.is_valid {
                    println!(
                        "✓ Directory integrity verified: all {} files match manifest digests!",
                        dir_report.matched_files
                    );
                } else {
                    println!("✗ Directory integrity check failed!");
                    if !dir_report.root_digest_match {
                        println!(
                            "  Root digest mismatch! Expected {}, computed {}",
                            dir_report.expected_root_digest, dir_report.computed_root_digest
                        );
                    }
                    if !dir_report.missing_files.is_empty() {
                        println!("  Missing files ({}):", dir_report.missing_files.len());
                        for f in &dir_report.missing_files {
                            println!("    - {}", f);
                        }
                    }
                    if !dir_report.altered_files.is_empty() {
                        println!(
                            "  Altered/corrupted files ({}):",
                            dir_report.altered_files.len()
                        );
                        for f in &dir_report.altered_files {
                            println!("    - {}", f);
                        }
                    }
                    return Err("Directory contents do not match manifest".into());
                }
            }
        }

        Commands::BundlePackage {
            dir,
            output,
            manifest,
            package_id,
            title,
            version,
            publisher_name,
            license_type,
            license_url,
            license_attribution,
            algorithm,
            no_progress,
        } => {
            println!(
                "Packaging compendium from {:?} into .ktome archive {:?}",
                dir, output
            );
            let parsed_manifest = if let Some(man_path) = manifest {
                let content = std::fs::read_to_string(&man_path)?;
                serde_json::from_str::<publisher::PackageManifest>(&content)?
            } else {
                let pkg_id = package_id.unwrap_or_else(|| {
                    dir.file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string()
                });
                let pkg_title = title.unwrap_or_else(|| pkg_id.clone());
                let pkg_ver = version.unwrap_or_else(|| "1.0.0".to_string());
                let pub_name =
                    publisher_name.unwrap_or_else(|| "Open Gaming Publisher".to_string());
                let digest_algo: kryptotome_core::DigestAlgorithm = algorithm.parse()?;
                let license_enum: license::OpenGameLicenseType = license_type.parse()?;
                let url = license_url.unwrap_or_else(|| license_enum.canonical_url().to_string());
                let attribution = license_attribution.unwrap_or_else(|| match license_enum {
                    license::OpenGameLicenseType::Cc0_1_0 => "".to_string(),
                    _ => format!("Published by {}", pub_name),
                });

                let lic = publisher::PackageLicense {
                    r#type: license_enum.as_str().to_string(),
                    url,
                    attribution,
                };

                let mut csprng = OsRng;
                let signing_key = SigningKey::generate(&mut csprng);
                let toolchain = publisher::PublisherToolchain::new(signing_key);
                let scan_opts = scanner::ScanOptions {
                    algorithm: digest_algo,
                    show_progress: !no_progress,
                };

                toolchain.build_and_sign_package_with_license(
                    &pkg_id, &pkg_title, &pkg_ver, &pub_name, &dir, scan_opts, lic,
                )?
            };

            let report =
                bundle::build_ktome_archive(&parsed_manifest, &dir, &output, !no_progress)?;
            println!("✓ Successfully bundled .ktome release archive!");
            println!("  Package: '{}' ({})", report.package_id, report.version);
            println!("  Archive: {:?}", report.archive_path);
            println!(
                "  Archive size: {}",
                indicatif::HumanBytes(report.archive_size_bytes)
            );
            println!("  Total files: {}", report.total_files_bundled);
            println!("  Root digest: {}", report.root_digest);
        }

        Commands::UnpackPackage {
            bundle,
            output,
            verify,
            no_progress,
        } => {
            println!("Unpacking .ktome archive {:?} into {:?}...", bundle, output);
            let report = bundle::unpack_ktome_archive(&bundle, &output, verify, !no_progress)?;
            println!("✓ Archive successfully unpacked!");
            println!("  Package: '{}' ({})", report.package_id, report.version);
            println!("  Extracted directory: {:?}", report.extracted_dir);
            println!("  Files extracted: {}", report.extracted_files);

            if let Some(man_rep) = report.manifest_verified {
                println!(
                    "✓ Manifest signature verified against key: {}",
                    man_rep.verifying_key_hex
                );
            }
            if let Some(dir_rep) = report.directory_integrity {
                if dir_rep.is_valid {
                    println!(
                        "✓ Extracted file integrity verified: all {} files match digests",
                        dir_rep.matched_files
                    );
                }
            }
        }

        Commands::BatchSign {
            source_dir,
            spec,
            output_dir,
            publisher_name,
            version,
            license_type,
            secret_key,
            no_progress,
        } => {
            println!(
                "Executing batch signing and release packaging into {:?}...",
                output_dir
            );
            let batch_spec = if let Some(spec_path) = spec {
                let content = std::fs::read_to_string(&spec_path)?;
                serde_json::from_str::<batch::BatchSignSpec>(&content)?
            } else if let Some(src_dir) = source_dir {
                batch::auto_discover_batch_spec(&src_dir, &publisher_name, &version, &license_type)?
            } else {
                return Err(
                    "Either --source-dir or --spec must be specified for batch signing".into(),
                );
            };

            let signing_key = if let Some(key_hex) = secret_key {
                let bytes =
                    publisher::hex_decode(&key_hex).map_err(|_| "Invalid secret key hex")?;
                if bytes.len() != 32 {
                    return Err("Secret key must be 32 bytes".into());
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some(SigningKey::from_bytes(&arr))
            } else {
                None
            };

            let report =
                batch::execute_batch_sign(batch_spec, &output_dir, signing_key, !no_progress)?;
            println!("✓ Batch signing completed successfully!");
            println!(
                "  Publisher: {} ({})",
                report.publisher_name, report.publisher_public_key
            );
            println!(
                "  Total packages signed and bundled: {}",
                report.total_packages
            );
            for pkg in &report.packages {
                println!(
                    "  • {} ({}) -> {:?} ({})",
                    pkg.title,
                    pkg.package_id,
                    pkg.bundle_path,
                    indicatif::HumanBytes(pkg.bundle_size_bytes)
                );
            }
            println!(
                "  Release summary saved to {:?}",
                output_dir.join("batch-summary.json")
            );
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

        Commands::TableBeacon {
            session_id,
            table_name,
            bind,
            packages,
        } => {
            let config = kryptotome_cli::table_beacon::TableBeaconConfig {
                session_id,
                table_name,
                bind_address: bind,
                advertised_service: "_kryptotome-table._tcp".to_string(),
                campaign_package_ids: packages,
            };
            let beacon = kryptotome_cli::table_beacon::AirGappedTableBeaconDaemon::new(config);
            let state = beacon.start();
            println!("==================================================");
            println!("  Kryptotome Air-Gapped Table Beacon Active");
            println!("==================================================");
            println!("Session ID: {}", mask_sensitive_id(&state.session_id));
            println!("Table Name: {}", state.table_name);
            println!("Bind Address: {}", state.bind_address);
            println!("mDNS Service: {}", state.advertised_service);
            println!("Zero Internet Required. Standing by for peer handshakes...");
        }

        Commands::TournamentCheckIn { qr_string, file } => {
            let ticket = if let Some(ref qr) = qr_string {
                kryptotome_cli::tournament::TournamentCheckInTicket::from_qr_string(qr)?
            } else if let Some(ref path) = file {
                let json = std::fs::read_to_string(path)?;
                serde_json::from_str(&json)?
            } else {
                return Err("Must provide either --qr-string or --file".into());
            };

            let result = kryptotome_cli::tournament::TournamentScanner::verify_ticket(&ticket)?;
            println!("==================================================");
            println!("  Tournament Check-In Verification: SUCCESS");
            println!("==================================================");
            println!("Tournament ID: {}", result.tournament_id);
            println!("Character Name: {}", result.character_name);
            println!("Verified Feats: {}", result.verified_feats_count);
            println!(
                "Verification Latency: {:.3}ms (Target: < 10ms)",
                result.latency_ms
            );
            println!("PII Protected: {}", !result.contains_pii);
            println!("Verified At: {}", result.verified_at);
        }
    }

    Ok(())
}

fn mask_sensitive_id(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 8 {
        return "[redacted]".to_string();
    }

    let prefix: String = chars.iter().take(4).collect();
    let suffix: String = chars
        .iter()
        .rev()
        .take(4)
        .cloned()
        .collect::<Vec<char>>()
        .into_iter()
        .rev()
        .collect();

    format!("{prefix}...{suffix}")
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
