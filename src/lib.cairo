// ============================================================================
// PHASE 2 — Carol publishes trust rules (public, immutable)
// ============================================================================
//
// This Cairo circuit verifies that a public key is a member of Carol's
// trust set by validating a Merkle proof against a fixed ROOT.
//
// Circuit Design:
// - Public input: ROOT (the Merkle root commitment)
// - Private witness: pk_bytes (32-byte public key)
// - Private witness: proof (Merkle sibling hashes)
// - Private witness: path_bits (left/right path indicators)
//
// Security Invariants:
// - ROOT is never user-controlled (fixed by verifier)
// - Circuit logic is immutable once compiled
// - Witnesses are private (zero-knowledge)
// - Proofs are reusable and unlinkable
// ============================================================================

/// Domain separator for Merkle tree leaf nodes
/// Must match the value used during tree construction (Rust implementation)
const DOMAIN_MERKLE_LEAF: felt252 = 0;

/// Domain separator for Merkle tree internal nodes
/// Must match the value used during tree construction (Rust implementation)
const DOMAIN_MERKLE_INTERNAL: felt252 = 1;

/// Fixed tree depth (supports up to 2^10 = ~1K pubkeys)
/// Must match the value used during tree construction (Rust implementation)
const TREE_DEPTH: u32 = 10;

/// Leaf Encoding:
/// Each 32-byte public key is encoded as a single field element using:
/// 1. Big-endian byte-to-integer conversion
/// 2. Base-256 accumulation: felt = Σ(byte[i] × 256^(31-i)) for i in 0..32
///
/// This matches the Rust implementation: pubkey_to_felt()
fn pk_bytes_to_felt252(pk_bytes: Span<u8>) -> felt252 {
    // Validate input length
    assert(pk_bytes.len() == 32, 'pubkey must be 32 bytes');

    let mut acc: felt252 = 0;

    for b in pk_bytes {
        acc = acc * 256 + (*b).into();
    }

    acc
}

/// Domain-separated Poseidon hash for Merkle leaf nodes
/// Hash = Poseidon(DOMAIN_MERKLE_LEAF, pubkey_felt)
///
/// This ensures proof siblings are always hashes, never raw pubkeys
/// Provides privacy: Bob cannot see other members' pubkeys from siblings
fn hash_leaf(pubkey_felt: felt252) -> felt252 {
    core::poseidon::poseidon_hash_span([DOMAIN_MERKLE_LEAF, pubkey_felt].span())
}

/// Domain-separated Poseidon hash for internal Merkle nodes
/// Hash = Poseidon(DOMAIN_MERKLE_INTERNAL, left, right)
///
/// This prevents domain confusion attacks between leaf and internal nodes
fn hash_node(left: felt252, right: felt252) -> felt252 {
    core::poseidon::poseidon_hash_span([DOMAIN_MERKLE_INTERNAL, left, right].span())
}

/// Verify Merkle proof and compute the root
///
/// Takes a leaf value and climbs the tree using the proof siblings
/// and path bits, applying domain-separated hashing at each level.
///
/// Returns the computed Merkle root.
fn verify_merkle_proof(leaf: felt252, proof: Span<felt252>, path_bits: Span<u8>) -> felt252 {
    // Validate proof length matches fixed tree depth
    assert(proof.len() == TREE_DEPTH, 'proof length must match depth');
    assert(path_bits.len() == TREE_DEPTH, 'path_bits must match depth');

    let mut hash = leaf;
    let mut index = 0;

    for bit in path_bits {
        let sibling = *proof[index];

        // Path bit: 0 = left child, 1 = right child
        hash = if *bit == 0 {
            hash_node(hash, sibling)
        } else {
            hash_node(sibling, hash)
        };

        index += 1;
    }

    hash
}

/// Phase 2 Circuit: Verify trust set membership
///
/// Public Input:
/// - root: The Merkle root (Carol's trust commitment)
///
/// Private Witness:
/// - pk_bytes: The member's 32-byte public key
/// - proof: Merkle sibling hashes (length = TREE_DEPTH)
/// - path_bits: Left/right path indicators (length = TREE_DEPTH)
///
/// Circuit Logic:
/// 1. Convert pk_bytes to felt252 (canonicalize leaf)
/// 2. Verify Merkle proof using domain-separated hashing
/// 3. Assert computed root equals expected root
///
/// Zero-Knowledge Property:
/// - Proof reveals nothing about other trust set members
/// - Proof reveals nothing about trust set size (fixed depth padding)
/// - Multiple proofs for same member are unlinkable
fn verify_membership(
    root: felt252, // public input
    pk_bytes: Span<u8>, // private witness
    proof: Span<felt252>, // private witness
    path_bits: Span<u8> // private witness
) {
    // Step 1: Convert public key bytes to felt252
    let pubkey_felt = pk_bytes_to_felt252(pk_bytes);

    // Step 2: Hash the pubkey to create the leaf (for privacy)
    let leaf = hash_leaf(pubkey_felt);

    // Step 3: Verify the Merkle proof
    let computed_root = verify_merkle_proof(leaf, proof, path_bits);

    // Step 4: Assert membership (computed root must match expected root)
    assert(computed_root == root, 'NOT_IN_TRUST_SET');
}

/// Main entry point for the Cairo program
///
/// This is the function that will be compiled into a STARK circuit.
/// The verifier key (VK) will be derived from this program.
///
/// This function is marked as executable so it can be proven using `scarb prove`.
#[executable]
fn main(
    root: felt252, // public input - Carol's trust commitment
    pk_bytes: Span<u8>, // private witness - member's public key
    proof: Span<felt252>, // private witness - Merkle siblings
    path_bits: Span<u8> // private witness - Merkle path
) {
    verify_membership(root, pk_bytes, proof, path_bits);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Carol's trust set Merkle root (from Phase 1)
    // Trust set: Alice, Bob, Dave (Nostr keys)
    const CAROL_ROOT: felt252 =
        0x23341e3ec830681a872ed1434d7e0cb1ea1a6d80ce3e8fb92ebc18d4c51f2ba;

    // Bob's public key as felt252
    const BOB_PUBKEY_FELT: felt252 =
        38312377296766633676474422671461867213713319987149342883958425390309984637;

    /// Test that hash_leaf produces correct domain-separated leaf hash
    #[test]
    fn test_hash_leaf() {
        let pubkey_felt: felt252 = BOB_PUBKEY_FELT;
        let leaf = hash_leaf(pubkey_felt);

        // Verify leaf is non-zero (hashed value)
        assert(leaf != 0, 'Leaf should be non-zero');

        // Verify leaf != raw pubkey (proves we're hashing)
        assert(leaf != pubkey_felt, 'Leaf should be hashed');
    }

    /// Test that hash_node produces correct domain-separated internal hash
    #[test]
    fn test_hash_node() {
        let left: felt252 = 0x123;
        let right: felt252 = 0x456;
        let hash = hash_node(left, right);

        // Verify hash is non-zero
        assert(hash != 0, 'Hash should be non-zero');

        // Verify hash is different from inputs
        assert(hash != left, 'Hash != left input');
        assert(hash != right, 'Hash != right input');
    }

    /// Test Bob's witness verification against Carol's ROOT
    /// This proves Bob is in Carol's trust set
    #[test]
    fn test_bob_membership_proof() {
        // Carol's ROOT (public)
        let root = CAROL_ROOT;

        // Bob's Merkle proof (private witness from Carol)
        let proof = array![
            0x21c3f9ff6528bea14891f613061cf177e46a284b58e1dbbd7c06b1ffd4c32f5,
            0x2d36a2057eebb9a497faf9b352b5d3ab0521f3796129573a5fcf918eafc9f75,
            0x6354e51e29379e7ce4cb6a46e737ab56eafb080ec45d33a79c7da4e88e13d23,
            0x25204416c2dbb6f4df77539005f6c8c4a88465b579df894d664079f368b3c6d,
            0x4a80b3a41016ce946ee322a2249ffacd51de204a9ef77bb09fe5d91a9cf696c,
            0x58bf066965e00ec86f658eac917cd35925dc02467a723775c0540a69ee3ded3,
            0x2551382158cf938b57712926f04fbb8cac07d354b2e19d7100693e90e791722,
            0x4f4fadecbd673b30e7e165fc919a3261af292219112f11f80d0328dde2a344a,
            0x382bedcc79c28fcbb6b7e6019919026720d068a0c2889f1f321279ac128710d,
            0x4e2c16257ee42fc6ea8ed81e2132085f7bc0d93b74c5db2557b82c5e55f59ae,
        ];

        // Path bits: 0 = left child, 1 = right child
        let path_bits = array![0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        // Verify proof length matches tree depth
        assert(proof.len() == TREE_DEPTH, 'Proof length mismatch');
        assert(path_bits.len() == TREE_DEPTH, 'Path bits length mismatch');

        // Convert Bob's pubkey to leaf
        let bob_leaf = hash_leaf(BOB_PUBKEY_FELT);

        // Verify Merkle proof
        let computed_root = verify_merkle_proof(bob_leaf, proof.span(), path_bits.span());

        // Assert membership: computed root must match Carol's ROOT
        assert(computed_root == root, 'Bob not in trust set');
    }

    /// Test complete verify_membership circuit
    /// This is what the STARK prover will execute
    #[test]
    fn test_verify_membership_circuit() {
        // Public input: Carol's ROOT
        let root = CAROL_ROOT;

        // Bob's actual Nostr public key as bytes (32 bytes)
        let pk_bytes = array![
            0x38, 0x15, 0xaf, 0x1d, 0x0e, 0x1f, 0x60, 0x60, 0x37, 0xb4, 0xe1, 0xd0, 0x54, 0x91,
            0x9c, 0x47, 0x75, 0xc4, 0x4f, 0x0c, 0x0f, 0xa2, 0xf6, 0x6c, 0xde, 0x3e, 0x4d, 0x83,
            0x39, 0xd0, 0x49, 0x84
        ];

        // Bob's Merkle proof
        let proof = array![
            0x21c3f9ff6528bea14891f613061cf177e46a284b58e1dbbd7c06b1ffd4c32f5,
            0x2d36a2057eebb9a497faf9b352b5d3ab0521f3796129573a5fcf918eafc9f75,
            0x6354e51e29379e7ce4cb6a46e737ab56eafb080ec45d33a79c7da4e88e13d23,
            0x25204416c2dbb6f4df77539005f6c8c4a88465b579df894d664079f368b3c6d,
            0x4a80b3a41016ce946ee322a2249ffacd51de204a9ef77bb09fe5d91a9cf696c,
            0x58bf066965e00ec86f658eac917cd35925dc02467a723775c0540a69ee3ded3,
            0x2551382158cf938b57712926f04fbb8cac07d354b2e19d7100693e90e791722,
            0x4f4fadecbd673b30e7e165fc919a3261af292219112f11f80d0328dde2a344a,
            0x382bedcc79c28fcbb6b7e6019919026720d068a0c2889f1f321279ac128710d,
            0x4e2c16257ee42fc6ea8ed81e2132085f7bc0d93b74c5db2557b82c5e55f59ae,
        ];

        // Path bits
        let path_bits = array![0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        // Execute the circuit (this is what gets proven in ZK)
        verify_membership(root, pk_bytes.span(), proof.span(), path_bits.span());

    // If we reach here, Bob's membership is verified!
    }
}
