use crate::publisher::PackageLicense;
use kryptotome_core::error::{KryptotomeError, KryptotomeErrorCode, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Supported open gaming and creative compendium licenses
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OpenGameLicenseType {
    /// Paizo Open RPG Creative License (ORC 1.0)
    #[serde(rename = "ORC-1.0")]
    Orc1_0,

    /// Creative Commons Attribution 4.0 International
    #[serde(rename = "CC-BY-4.0")]
    CcBy4_0,

    /// Creative Commons CC0 1.0 Universal (Public Domain Dedication)
    #[serde(rename = "CC0-1.0")]
    Cc0_1_0,

    /// Custom Open Gaming License (e.g. OGL 1.0a, Free League Workshop, etc.)
    #[serde(rename = "Custom-Open")]
    CustomOpen,
}

impl OpenGameLicenseType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Orc1_0 => "ORC-1.0",
            Self::CcBy4_0 => "CC-BY-4.0",
            Self::Cc0_1_0 => "CC0-1.0",
            Self::CustomOpen => "Custom-Open",
        }
    }

    /// Official canonical URL for the license
    pub fn canonical_url(&self) -> &'static str {
        match self {
            Self::Orc1_0 => "https://paizo.com/orclicense",
            Self::CcBy4_0 => "https://creativecommons.org/licenses/by/4.0/",
            Self::Cc0_1_0 => "https://creativecommons.org/publicdomain/zero/1.0/",
            Self::CustomOpen => "https://kryptotome.org/licenses/custom-open",
        }
    }

    /// Whether non-empty attribution / notice is legally mandatory
    pub fn requires_attribution(&self) -> bool {
        match self {
            Self::Orc1_0 => true,
            Self::CcBy4_0 => true,
            Self::Cc0_1_0 => false,
            Self::CustomOpen => true,
        }
    }

    /// Returns human-readable description of license obligations
    pub fn description(&self) -> &'static str {
        match self {
            Self::Orc1_0 => "Paizo Open RPG Creative (ORC 1.0) - Irrevocable open gaming license requiring ORC Notice attribution",
            Self::CcBy4_0 => "Creative Commons Attribution 4.0 International - Free distribution with creator attribution",
            Self::Cc0_1_0 => "Creative Commons CC0 1.0 Universal - Public domain dedication, attribution optional",
            Self::CustomOpen => "Custom Open Gaming License - Requires declared terms and attribution",
        }
    }
}

impl fmt::Display for OpenGameLicenseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for OpenGameLicenseType {
    type Err = KryptotomeError;

    fn from_str(s: &str) -> Result<Self> {
        let normalized = s.trim().to_uppercase();
        match normalized.as_str() {
            "ORC" | "ORC-1.0" | "ORC1.0" | "ORC-1" => Ok(Self::Orc1_0),
            "CC-BY" | "CC-BY-4.0" | "CCBY4.0" | "CCBY-4.0" | "CC-BY-4" => Ok(Self::CcBy4_0),
            "CC0" | "CC0-1.0" | "CC-0" | "CC01.0" => Ok(Self::Cc0_1_0),
            "CUSTOM-OPEN" | "CUSTOM" | "OPEN" => Ok(Self::CustomOpen),
            _ => Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp106InvalidManifestSchema,
                message: format!(
                    "Unsupported license type '{}'. Supported open gaming licenses: 'ORC-1.0', 'CC-BY-4.0', 'CC0-1.0', 'Custom-Open'",
                    s
                ),
            }),
        }
    }
}

/// Validates package license metadata against open gaming license standards
pub fn validate_license_metadata(license: &PackageLicense) -> Result<OpenGameLicenseType> {
    // 1. Validate license type string conforms to known open gaming license
    let license_type = OpenGameLicenseType::from_str(&license.r#type)?;

    // 2. Validate license URL format
    let url = license.url.trim();
    if url.is_empty() {
        return Err(KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp106InvalidManifestSchema,
            message: format!(
                "License URL cannot be empty for license type '{}'",
                license.r#type
            ),
        });
    }

    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp106InvalidManifestSchema,
            message: format!(
                "Invalid license URI format '{}'. Must be an http(s) URL",
                url
            ),
        });
    }

    // 3. Validate specific license requirements
    match license_type {
        OpenGameLicenseType::Orc1_0 => {
            if license.attribution.trim().is_empty() {
                return Err(KryptotomeError::Detailed {
                    code: KryptotomeErrorCode::Kryp106InvalidManifestSchema,
                    message: "Paizo ORC license requires non-empty attribution metadata (ORC Notice & publisher identity)".to_string(),
                });
            }
        }
        OpenGameLicenseType::CcBy4_0 => {
            if license.attribution.trim().is_empty() {
                return Err(KryptotomeError::Detailed {
                    code: KryptotomeErrorCode::Kryp106InvalidManifestSchema,
                    message:
                        "Creative Commons CC-BY-4.0 license requires non-empty attribution metadata"
                            .to_string(),
                });
            }
        }
        OpenGameLicenseType::Cc0_1_0 => {
            // Attribution is legally optional for CC0 public domain dedication
        }
        OpenGameLicenseType::CustomOpen => {
            if license.attribution.trim().is_empty() {
                return Err(KryptotomeError::Detailed {
                    code: KryptotomeErrorCode::Kryp106InvalidManifestSchema,
                    message: "Custom-Open license requires non-empty attribution metadata"
                        .to_string(),
                });
            }
        }
    }

    Ok(license_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_license_parsing() {
        assert_eq!(
            OpenGameLicenseType::from_str("ORC-1.0").unwrap(),
            OpenGameLicenseType::Orc1_0
        );
        assert_eq!(
            OpenGameLicenseType::from_str("orc").unwrap(),
            OpenGameLicenseType::Orc1_0
        );
        assert_eq!(
            OpenGameLicenseType::from_str("CC-BY-4.0").unwrap(),
            OpenGameLicenseType::CcBy4_0
        );
        assert_eq!(
            OpenGameLicenseType::from_str("cc-by").unwrap(),
            OpenGameLicenseType::CcBy4_0
        );
        assert_eq!(
            OpenGameLicenseType::from_str("CC0-1.0").unwrap(),
            OpenGameLicenseType::Cc0_1_0
        );
        assert_eq!(
            OpenGameLicenseType::from_str("cc0").unwrap(),
            OpenGameLicenseType::Cc0_1_0
        );
        assert_eq!(
            OpenGameLicenseType::from_str("Custom-Open").unwrap(),
            OpenGameLicenseType::CustomOpen
        );
        assert!(OpenGameLicenseType::from_str("GPL-3.0").is_err());
    }

    #[test]
    fn test_orc_validation() {
        let valid_orc = PackageLicense {
            r#type: "ORC-1.0".to_string(),
            url: "https://paizo.com/orclicense".to_string(),
            attribution: "Published by Paizo Inc. Pathfinder Core Rulebook (c) 2023".to_string(),
        };
        assert!(validate_license_metadata(&valid_orc).is_ok());

        let missing_attr_orc = PackageLicense {
            r#type: "ORC-1.0".to_string(),
            url: "https://paizo.com/orclicense".to_string(),
            attribution: "   ".to_string(),
        };
        assert!(validate_license_metadata(&missing_attr_orc).is_err());
    }

    #[test]
    fn test_cc_by_validation() {
        let valid_cc_by = PackageLicense {
            r#type: "CC-BY-4.0".to_string(),
            url: "https://creativecommons.org/licenses/by/4.0/".to_string(),
            attribution: "5e System Reference Document 5.1 (c) Wizards of the Coast".to_string(),
        };
        assert!(validate_license_metadata(&valid_cc_by).is_ok());

        let empty_attr_cc_by = PackageLicense {
            r#type: "CC-BY-4.0".to_string(),
            url: "https://creativecommons.org/licenses/by/4.0/".to_string(),
            attribution: "".to_string(),
        };
        assert!(validate_license_metadata(&empty_attr_cc_by).is_err());
    }

    #[test]
    fn test_cc0_validation() {
        // CC0 permits empty attribution
        let valid_cc0 = PackageLicense {
            r#type: "CC0-1.0".to_string(),
            url: "https://creativecommons.org/publicdomain/zero/1.0/".to_string(),
            attribution: "".to_string(),
        };
        assert!(validate_license_metadata(&valid_cc0).is_ok());

        let valid_cc0_with_attr = PackageLicense {
            r#type: "CC0-1.0".to_string(),
            url: "https://creativecommons.org/publicdomain/zero/1.0/".to_string(),
            attribution: "Public domain monster tokens by Forgotten Adventures".to_string(),
        };
        assert!(validate_license_metadata(&valid_cc0_with_attr).is_ok());
    }

    #[test]
    fn test_invalid_url() {
        let bad_url = PackageLicense {
            r#type: "CC0-1.0".to_string(),
            url: "ftp://not-a-web-url".to_string(),
            attribution: "".to_string(),
        };
        assert!(validate_license_metadata(&bad_url).is_err());
    }
}
