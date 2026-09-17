use crate::circuit::string_to_scalar;
use crate::curve::ScalarField;
use crate::error::{KryptotomeError, KryptotomeErrorCode, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// An individual item in a compendium tree (spell, monster stat block, feat, rule)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompendiumItem {
    pub id: String,
    pub item_type: String,
    pub digest: String,
}

impl CompendiumItem {
    pub fn new(id: impl Into<String>, item_type: impl Into<String>, digest: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            item_type: item_type.into(),
            digest: digest.into(),
        }
    }

    /// Computes deterministic leaf hash: Sha256("kryptotome:leaf:" || id || ":" || item_type || ":" || digest)
    pub fn compute_leaf_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"kryptotome:leaf:");
        hasher.update(self.id.as_bytes());
        hasher.update(b":");
        hasher.update(self.item_type.as_bytes());
        hasher.update(b":");
        hasher.update(self.digest.as_bytes());
        hasher.finalize().into()
    }

    /// Converts leaf hash to BLS12-381 ScalarField
    pub fn to_scalar(&self) -> ScalarField {
        let hash = self.compute_leaf_hash();
        string_to_scalar(&hex::encode(hash))
    }
}

/// A node along a Merkle inclusion path
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerklePathNode {
    pub sibling: String, // Hex-encoded 32-byte hash
    pub is_left: bool,   // True if sibling is left of current node, False if right
}

/// Cryptographic Merkle inclusion proof certifying an item belongs to a compendium root
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleInclusionProof {
    pub item: CompendiumItem,
    pub leaf_index: usize,
    pub path: Vec<MerklePathNode>,
    pub root: String, // Hex-encoded root
}

impl MerkleInclusionProof {
    /// Verifies the Merkle inclusion proof against expected root (or self.root)
    pub fn verify(&self, expected_root_hex: Option<&str>) -> bool {
        let target_root = expected_root_hex.unwrap_or(&self.root);
        let mut current_hash = self.item.compute_leaf_hash();

        for step in &self.path {
            let sibling_bytes = match hex::decode(&step.sibling) {
                Ok(b) if b.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    arr
                }
                _ => return false,
            };

            let mut hasher = Sha256::new();
            hasher.update(b"kryptotome:node:");
            if step.is_left {
                hasher.update(&sibling_bytes);
                hasher.update(&current_hash);
            } else {
                hasher.update(&current_hash);
                hasher.update(&sibling_bytes);
            }
            current_hash = hasher.finalize().into();
        }

        hex::encode(current_hash) == target_root.to_lowercase()
    }
}

/// Deterministic binary Merkle tree over compendium items
#[derive(Debug, Clone)]
pub struct CompendiumMerkleTree {
    items: Vec<CompendiumItem>,
    layers: Vec<Vec<[u8; 32]>>,
}

impl CompendiumMerkleTree {
    /// Constructs a Merkle tree over a list of compendium items
    pub fn new(items: Vec<CompendiumItem>) -> Result<Self> {
        if items.is_empty() {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp603EntitlementNotFound,
                message: "Cannot construct a compendium Merkle tree with 0 items".to_string(),
            });
        }


        let mut current_layer: Vec<[u8; 32]> = items.iter().map(|it| it.compute_leaf_hash()).collect();
        let mut layers = vec![current_layer.clone()];

        while current_layer.len() > 1 {
            let mut next_layer = Vec::with_capacity((current_layer.len() + 1) / 2);
            for chunk in current_layer.chunks(2) {
                if chunk.len() == 2 {
                    let mut hasher = Sha256::new();
                    hasher.update(b"kryptotome:node:");
                    hasher.update(&chunk[0]);
                    hasher.update(&chunk[1]);
                    next_layer.push(hasher.finalize().into());
                } else {
                    // Odd number of leaves: duplicate last element
                    let mut hasher = Sha256::new();
                    hasher.update(b"kryptotome:node:");
                    hasher.update(&chunk[0]);
                    hasher.update(&chunk[0]);
                    next_layer.push(hasher.finalize().into());
                }
            }
            layers.push(next_layer.clone());
            current_layer = next_layer;
        }

        Ok(Self { items, layers })
    }

    /// Root hash of the Merkle tree
    pub fn root(&self) -> [u8; 32] {
        self.layers.last().expect("Tree must have root layer")[0]
    }

    /// Hex-encoded root hash
    pub fn root_hex(&self) -> String {
        hex::encode(self.root())
    }

    /// Converts root hash to BLS12-381 ScalarField
    pub fn root_scalar(&self) -> ScalarField {
        string_to_scalar(&self.root_hex())
    }

    /// Generates a Merkle inclusion proof for the item with specified id
    pub fn generate_proof(&self, item_id: &str) -> Result<MerkleInclusionProof> {
        let leaf_idx = self
            .items
            .iter()
            .position(|it| it.id == item_id)
            .ok_or_else(|| KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp603EntitlementNotFound,
                message: format!("Item '{}' not found in compendium Merkle tree", item_id),
            })?;


        let item = self.items[leaf_idx].clone();
        let mut path = Vec::new();
        let mut current_idx = leaf_idx;

        for layer in &self.layers[0..self.layers.len() - 1] {
            let is_right_child = current_idx % 2 == 1;
            let sibling_idx = if is_right_child {
                current_idx - 1
            } else if current_idx + 1 < layer.len() {
                current_idx + 1
            } else {
                current_idx // Duplicated sibling for odd layer length
            };

            path.push(MerklePathNode {
                sibling: hex::encode(layer[sibling_idx]),
                is_left: is_right_child, // If current is right, sibling is left
            });

            current_idx /= 2;
        }

        Ok(MerkleInclusionProof {
            item,
            leaf_index: leaf_idx,
            path,
            root: self.root_hex(),
        })
    }

    pub fn items(&self) -> &[CompendiumItem] {
        &self.items
    }
}

impl fmt::Display for CompendiumMerkleTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CompendiumMerkleTree(items={}, root={})",
            self.items.len(),
            self.root_hex()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_root_and_inclusion_proof() {
        let items = vec![
            CompendiumItem::new("spell:fireball", "spell", "sha256:1111111111111111111111111111111111111111111111111111111111111111"),
            CompendiumItem::new("spell:magic-missile", "spell", "sha256:2222222222222222222222222222222222222222222222222222222222222222"),
            CompendiumItem::new("monster:red-dragon", "monster", "sha256:3333333333333333333333333333333333333333333333333333333333333333"),
        ];

        let tree = CompendiumMerkleTree::new(items.clone()).unwrap();
        assert_eq!(tree.items().len(), 3);
        assert!(!tree.root_hex().is_empty());

        // Generate proof for second item (magic-missile)
        let proof = tree.generate_proof("spell:magic-missile").unwrap();
        assert_eq!(proof.item.id, "spell:magic-missile");
        assert_eq!(proof.root, tree.root_hex());
        assert!(proof.verify(None));

        // Tamper test: Alter digest
        let mut tampered = proof.clone();
        tampered.item.digest = "sha256:badbadbad".to_string();
        assert!(!tampered.verify(None));

        // Tamper test: Alter sibling
        let mut tampered_sibling = proof.clone();
        tampered_sibling.path[0].sibling = hex::encode([0u8; 32]);
        assert!(!tampered_sibling.verify(None));
    }
}
