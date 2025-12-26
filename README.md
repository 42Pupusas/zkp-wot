# ZKP Web of Trust (zkp-wot)

A Zero-Knowledge Proof based Web of Trust protocol that allows users to prove membership in a trust set without revealing the witness data or other members.

## Overview

This project implements a privacy-preserving Web of Trust using STARK proofs and the Nostr protocol. It enables:

- **Private Membership Proofs**: Prove you're in someone's trust set without revealing your witness
- **Zero-Knowledge**: Proofs don't leak information about other trust set members
- **Decentralized**: All communication happens over Nostr relays
- **Verifiable**: Anyone can verify STARK proofs cryptographically

## The Three-Phase Protocol

### Phase 1: Trust Set Creation (Carol's Perspective)

**Who**: Carol (the trust set creator)
**What**: Creates a Merkle tree of trusted pubkeys and distributes encrypted witnesses

1. **Build Trust Set**: Carol selects trusted Nostr public keys (Alice, Bob, Dave, etc.)
2. **Compute Merkle Root**: Hash pubkeys into a fixed-depth (2^10) Merkle tree using Poseidon hash
3. **Generate Witnesses**: For each member, create a Merkle proof (siblings + path bits)
4. **Encrypt Witnesses**: Encrypt each witness using NIP-17 (gift-wrapped DMs)
5. **Distribute**: Send encrypted witnesses to members via Nostr relays

**Key Properties**:
- Each member receives only their own witness
- NIP-17 encryption ensures privacy (ephemeral keys + NIP-44 encryption)
- Carol can go offline after distribution

```rust
// Example from tests
let trust_set = vec![
    ALICE_NOSTR_KEY.public_key_slice(),
    BOB_NOSTR_KEY.public_key_slice(),
    DAVE_NOSTR_KEY.public_key_slice(),
];

let root = compute_merkle_root(&trust_set);
let (siblings, path_bits) = get_merkle_proof(&trust_set, &bob_pk).unwrap();
let witness = WitnessData::new(siblings, path_bits);

// Encrypt for Bob
let encrypted = witness.private_witness(&bob_pubkey, carol_signer)?;
```

### Phase 2: Circuit Publication (Carol's Perspective)

**Who**: Carol
**What**: Publishes the Cairo circuit that verifies membership proofs

1. **Compile Circuit**: Cairo program is compiled to Sierra JSON
2. **Create Nostr Note**: Package circuit with metadata (root, version, constants)
3. **Publish**: Post to Nostr relays as a signed, parameterized replaceable event (kind 30078)

**Circuit Metadata Tags**:
- `root`: Merkle root (0x-prefixed hex)
- `version`: Circuit version
- `domain_merkle_leaf`: Domain separator for leaf hashing
- `domain_merkle_internal`: Domain separator for internal node hashing
- `tree_depth`: Fixed tree depth (10)
- `circuit_type`: "cairo-sierra"

```rust
let circuit = Circuit::new(sierra_json, root);
let circuit_note = circuit.to_nostr_note(&carol_keypair)?;

// Publish to relay
relay.publish(circuit_note)?;
```

**Note Structure**:
- **Kind**: 30078 (parameterized replaceable event)
- **Content**: Complete Sierra JSON
- **Tags**: All circuit metadata
- **Signature**: Carol's signature (authenticity)
- **Note ID**: Hash of note (immutability)

### Phase 3: Proof Generation & Verification

#### Phase 3a: Bob Decrypts Witness

**Who**: Bob (trust set member)
**What**: Fetches and decrypts private witness from relay

1. **Fetch**: Get encrypted witness note from Nostr relay
2. **Decrypt**: Use NIP-17 decryption with Bob's private key
3. **Verify**: Confirm witness integrity

```rust
let encrypted_note = relay.fetch_dm(bob_pubkey)?;
let witness = WitnessData::decrypt_private_witness(
    &bob_witness_data,
    &bob_keypair,
    encrypted_note,
)?;
```

#### Phase 3b: Bob Generates STARK Proof

**Who**: Bob
**What**: Creates a zero-knowledge proof of membership

1. **Execute Cairo**: Run `scarb execute` with witness as arguments
2. **Generate Proof**: Run `scarb prove` using Stwo prover
3. **Share**: Make proof available (via Blossom/IPFS in production)

```rust
let (proof_data, proof_path) = witness.generate_proof(
    root,
    &bob_pk,
    circuit_id,
)?;

// In production: Upload to Blossom server, share CID
// For tests: Share file path directly
```

**STARK Proof Properties**:
- **Size**: ~2.4MB (too large for NIP-17, requires CDN)
- **Zero-Knowledge**: Doesn't reveal witness or other members
- **Verifiable**: Anyone can verify using `scarb verify`

#### Phase 3c: Alice Verifies Bob's Proof

**Who**: Alice (verifier)
**What**: Confirms Bob is in Carol's trust set

1. **Fetch Circuit**: Get Carol's published circuit from relay
2. **Verify Signature**: Confirm Carol signed the circuit
3. **Fetch Proof**: Get Bob's proof (via CID/path)
4. **Verify Proof**: Run `scarb verify` to cryptographically verify

```rust
// Fetch circuit
let circuit_note = relay.fetch_circuit(circuit_id)?;
assert!(circuit_note.verify()); // Carol's signature

// Fetch and verify proof
let proof_data = ProofData::from_file(&proof_path, circuit_id, root)?;
let verified = proof_data.verify()?;

assert!(verified); // Bob ∈ Carol's trust set ✓
```

**What Alice Learns**:
- ✓ Bob is in Carol's trust set
- ✓ The proof is cryptographically valid
- ✗ Bob's witness (remains private)
- ✗ Other trust set members (remain anonymous)

## Code Structure

### Core Modules

```
src/
├── lib.rs           # Main implementation
└── lib.cairo        # Cairo circuit for membership verification

Key Components:
- Circuit           # Cairo circuit wrapper with Nostr serialization
- ProofData         # STARK proof with verification methods
- WitnessData       # Merkle proof with encryption/decryption
```

### Main Types

#### `Circuit`
```rust
pub struct Circuit {
    pub sierra_json: String,  // Compiled Cairo circuit
    pub root: String,          // Merkle root (hex)
    pub version: u32,          // Circuit version
}

impl Circuit {
    fn new(sierra_json: String, root: Felt) -> Self;
    fn to_nostr_note(&self, signer: &NostrKeypair) -> Result<NostrNote>;
    fn from_nostr_note(note: &NostrNote) -> Result<Self>;
    fn root_felt(&self) -> Result<Felt>;
}
```

#### `ProofData`
```rust
pub struct ProofData {
    pub proof_json: String,    // STARK proof
    pub circuit_id: String,    // Circuit note ID
    pub root: String,          // Merkle root (hex)
    pub prover: String,        // "stwo"
}

impl ProofData {
    fn new(proof_json: String, circuit_id: String, root: Felt) -> Self;
    fn from_file(path: &str, circuit_id: String, root: Felt) -> Result<Self>;
    fn verify(&self) -> Result<bool>;  // Uses scarb verify
    fn save_to_file(&self, path: &str) -> Result<()>;
}
```

#### `WitnessData`
```rust
pub struct WitnessData {
    siblings: Vec<Vec<u8>>,    // Merkle siblings
    path_bits: Vec<u8>,        // Path through tree
}

impl WitnessData {
    fn new(siblings: Vec<Felt>, path_bits: Vec<u8>) -> Self;
    fn private_witness(&self, peer_pubkey: &str, signer: &NostrKeypair)
        -> Result<NostrNote>;  // NIP-17 encryption
    fn decrypt_private_witness(&self, signer: &NostrKeypair, note: &NostrNote)
        -> Result<Self>;  // NIP-17 decryption
    fn generate_proof(&self, root: Felt, pk: &[u8; 32], circuit_id: String)
        -> Result<(ProofData, String)>;  // STARK proof generation
}
```

### Cryptographic Primitives

- **Hash Function**: Poseidon (Starknet native)
- **Merkle Tree**: Fixed depth (2^10 = 1024 leaves)
- **Domain Separation**:
  - Leaf hashing: `"zkp-wot-merkle-leaf"`
  - Internal nodes: `"zkp-wot-merkle-internal"`
- **Proof System**: STARK (via Stwo prover)
- **Encryption**: NIP-44 (ECDH + ChaCha20)
- **Key Exchange**: NIP-17 (ephemeral sender keys)

## Running Tests

### Prerequisites

```bash
# Install Scarb (Cairo package manager)
curl --proto '=https' --tlsv1.2 -sSf https://docs.swmansion.com/scarb/install.sh | sh

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Build Cairo Circuit

```bash
# Compile Cairo to Sierra
scarb build

# This generates:
# - target/dev/zkp_wot_main.executable.sierra.json
```

### Run All Tests

```bash
# Run all 18 tests
cargo test --lib

# Run with output
cargo test --lib -- --nocapture
```

### Individual Test Suites

```bash
# Phase 1 tests (Trust set creation)
cargo test phase1 -- --nocapture

# Phase 2 tests (Circuit publication)
cargo test phase2 -- --nocapture

# Phase 3 tests (Proof generation & verification)
cargo test phase3 -- --nocapture
```

### Key Tests

- `phase1_complete_carol_workflow` - Full trust set creation with 4 members
- `phase2_publish_circuit_as_nostr_note` - Circuit publication to Nostr
- `phase3_bob_generates_stark_proof` - STARK proof generation
- `phase3_complete_bob_proves_alice_verifies` - End-to-end workflow

## Test Workflow Explained

### `phase1_complete_carol_workflow`

**Purpose**: Demonstrates complete trust set creation and witness distribution

**Steps**:
1. Carol creates trust set with 4 members (Alice, Bob, Charlie, Dave)
2. Computes Merkle root from sorted pubkeys
3. Generates Merkle proofs for all 4 members
4. Creates WitnessData for each member
5. Encrypts witnesses using NIP-17
6. Verifies each member can decrypt only their own witness
7. Verifies cross-decryption fails (Bob can't decrypt Alice's witness)

**Assertions**:
- All witnesses decrypt correctly for intended recipients
- Cross-decryption fails (privacy guarantee)

### `phase2_publish_circuit_as_nostr_note`

**Purpose**: Shows how Cairo circuits are published as Nostr notes

**Steps**:
1. Carol compiles Cairo circuit to Sierra JSON
2. Creates Circuit struct with root
3. Publishes as signed Nostr note (kind 30078)
4. Verifies note structure and metadata tags

**Assertions**:
- Note has correct kind (30078)
- All metadata tags present (root, version, constants)
- Carol's signature is valid
- Note ID provides immutability guarantee

### `phase3_bob_generates_stark_proof`

**Purpose**: Demonstrates STARK proof generation

**Steps**:
1. Bob has decrypted witness (siblings + path bits)
2. Calls `WitnessData::generate_proof()`
3. Internally runs:
   - `scarb execute` - Execute Cairo with witness
   - `scarb prove` - Generate STARK proof with Stwo
4. Returns ProofData and proof file path

**Output**:
- Execution ID from scarb execute
- Proof file (~2.4MB JSON)

### `phase3_complete_bob_proves_alice_verifies`

**Purpose**: End-to-end workflow simulating all parties and relay

**Steps**:

**Phase 1** (Carol):
1. Create trust set (Alice, Bob, Dave)
2. Compute Merkle root
3. Generate Bob's witness
4. Encrypt witness with NIP-17
5. Publish to simulated relay

**Phase 2** (Carol):
1. Load compiled Cairo circuit
2. Create Circuit struct
3. Publish circuit note to relay

**Phase 3a** (Bob):
1. Fetch encrypted witness from relay
2. Decrypt using NIP-17
3. Verify witness integrity

**Phase 3b** (Bob):
1. Generate STARK proof using witness
2. Share proof location with Alice (via relay)

**Phase 3c** (Alice):
1. Fetch Carol's circuit from relay
2. Verify Carol's signature
3. Extract root from circuit tags
4. Fetch Bob's proof
5. Verify proof using `ProofData::verify()`
6. Confirmation: Bob ∈ Carol's trust set ✓

**Privacy Properties Verified**:
- Bob's witness remains private (never shared)
- Proof is zero-knowledge (doesn't reveal witness)
- Other members remain anonymous
- Only membership fact is revealed
- All communication via Nostr relays
- STARK proof is cryptographically verifiable

## Cairo Circuit

The Cairo program (`src/lib.cairo`) implements Merkle proof verification:

```cairo
#[executable]
fn main(
    root: felt252,
    pk_bytes: Span<u8>,
    proof: Span<felt252>,      // Merkle siblings
    path_bits: Span<u8>         // Path through tree
) {
    verify_membership(root, pk_bytes, proof, path_bits);
}
```

**Verification Logic**:
1. Hash public key bytes to field element
2. Hash with domain separator for leaf
3. Iterate through tree levels:
   - If path_bit = 0: hash(current, sibling)
   - If path_bit = 1: hash(sibling, current)
4. Assert final hash equals root

## Production Considerations

### Proof Distribution

**Current**: File paths (for testing)
**Production**: Use Blossom CDN or IPFS

```rust
// Upload proof to Blossom
let cid = blossom_client.upload(&proof_data.proof_json)?;

// Share CID via Nostr
let note = NostrNote {
    content: cid,
    kind: 1,  // Regular note
    tags: vec![
        vec!["proof_cid", &cid],
        vec!["circuit_id", &circuit_note_id],
    ],
    ...
};
```

### Relay Integration

**Current**: HashMap simulation
**Production**: Real Nostr relays

```rust
// Connect to relays
let relay = nostr_sdk::Client::new(&keys);
relay.add_relay("wss://relay.damus.io").await?;
relay.add_relay("wss://relay.illuminodes.com").await?;

// Publish circuit
relay.publish_event(circuit_note).await?;

// Subscribe to encrypted DMs
let filter = Filter::new()
    .kind(14)  // Gift-wrapped DMs
    .pubkey(my_pubkey);
relay.subscribe(vec![filter]).await?;
```

### Trust Set Updates

To update a trust set:
1. Carol creates new Merkle root with updated members
2. Publishes new circuit (parameterized replaceable event overwrites old)
3. Generates new witnesses for all current members
4. Distributes via NIP-17

Previous proofs become invalid (different root).

## Security Notes

⚠️ **Warning**: Stwo prover is experimental
```
warn: soundness of proof is not yet guaranteed by Stwo, use at your own risk
```

**Privacy Guarantees**:
- ✓ Zero-knowledge proofs (don't reveal witness)
- ✓ Encrypted witness distribution (NIP-17)
- ✓ Anonymous membership (other members hidden)
- ✓ Verifiable without trusted setup

**Assumptions**:
- Elliptic curve discrete log (ECDH security)
- Collision resistance of Poseidon hash
- STARK soundness (when Stwo matures)
- Nostr relay availability (can use multiple)

## References

- [Cairo Book](https://book.cairo-lang.org/)
- [Scarb Documentation](https://docs.swmansion.com/scarb/)
- [Stwo Prover](https://github.com/starkware-libs/stwo)
- [NIP-17: Private Direct Messages](https://github.com/nostr-protocol/nips/blob/master/17.md)
- [NIP-44: Encryption](https://github.com/nostr-protocol/nips/blob/master/44.md)
- [Poseidon Hash](https://eprint.iacr.org/2019/458.pdf)

## License

MIT
