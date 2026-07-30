# python-merkle-proof-lab

Deterministic stdlib-only Merkle inclusion-proof correctness lab.

## Source audit

**Wikipedia – Merkle tree** https://en.wikipedia.org/wiki/Merkle_tree (rev 1359303374)
> "In cryptography and computer science, a hash tree or Merkle tree is a tree in which every 'leaf' node is labelled with the cryptographic hash of a data block, and every node that is not a leaf is labelled with the cryptographic hash of the labels of its child nodes."

Wikipedia is background only, not a wire-format standard.

**Python docs – hashlib** https://docs.python.org/3/library/hashlib.html
- `hashlib.sha256(data)` → hash object
- `.digest()` → 32-byte bytes
- `.hexdigest()` → lowercase hex

## Local tree-format policy

- Hash: SHA-256 via `hashlib.sha256`
- Leaf hash: `sha256(b"\x00" + len_be4 + leaf_bytes)`
- Internal: `sha256(b"\x01" + left + right)`
- Digest: 32 bytes
- Order: significant
- Odd width: duplicate final digest
- One leaf: root = leaf_hash(leaf)
- Empty: rejected (`empty_tree`)
- Display: lowercase hex

This defines one local format, not a universal standard.

## API

- `build_root(leaves: Sequence[bytes]) -> bytes`
- `build_proof(leaves, index) -> InclusionProof`
- `verify_proof(leaf, index, leaf_count, proof, expected_root) -> bool`

`ProofStep(sibling: bytes, side: 'left'|'right')`
`InclusionProof(leaf_index: int, leaf_count: int, steps: tuple[ProofStep,...])`

Errors: `EmptyTreeError`, `InvalidLeafError`, `IndexOutOfRangeError`, `InvalidDigestError`, `InvalidSideError`, `InvalidMetadataError`, `ProofLengthMismatchError`

## Observations

- One leaf → zero proof steps
- Three-leaf final leaf uses duplicated sibling at leaf level
- Five-leaf case exercises duplication at multiple levels
- Reordered leaves produce a different root
- Identical leaf bytes at different indexes have distinct positional proofs
- Reversed side → `root_mismatch`
- Unknown side → `invalid_side`
- Inclusion does not prove authorship, freshness, or consensus

## Results

See `RESULTS.md`. 26 cases, 24 independent unittests.

This lab does not establish production cryptographic security.
