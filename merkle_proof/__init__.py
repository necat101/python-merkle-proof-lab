import hashlib
from dataclasses import dataclass
from typing import Sequence, Literal, Tuple

class MerkleError(Exception): pass
class EmptyTreeError(MerkleError): pass
class InvalidLeafError(MerkleError): pass
class IndexOutOfRangeError(MerkleError): pass
class InvalidDigestError(MerkleError): pass
class InvalidSideError(MerkleError): pass
class InvalidMetadataError(MerkleError): pass
class ProofLengthMismatchError(MerkleError): pass

Side = Literal['left','right']

@dataclass(frozen=True)
class ProofStep:
    sibling: bytes
    side: Side

@dataclass(frozen=True)
class InclusionProof:
    leaf_index: int
    leaf_count: int
    steps: Tuple[ProofStep, ...]

def _is_int_not_bool(x): return type(x) is int
def _check_leaf(b):
    if type(b) is not bytes: raise InvalidLeafError(f'leaf must be bytes, got {type(b)}')
def _check_digest(d):
    if type(d) is not bytes or len(d)!=32: raise InvalidDigestError('digest must be 32 bytes')

def leaf_hash(data: bytes) -> bytes:
    _check_leaf(data)
    return hashlib.sha256(b'\x00' + len(data).to_bytes(4,'big') + data).digest()

def node_hash(left: bytes, right: bytes) -> bytes:
    _check_digest(left); _check_digest(right)
    return hashlib.sha256(b'\x01' + left + right).digest()

def _build_levels(leaves: Sequence[bytes]):
    if not leaves: raise EmptyTreeError('empty tree')
    level = []
    for b in leaves: _check_leaf(b); level.append(leaf_hash(b))
    levels=[level]
    while len(level)>1:
        if len(level)%2==1: level = level + [level[-1]]
        nxt=[]
        for i in range(0,len(level),2):
            nxt.append(node_hash(level[i], level[i+1]))
        level=nxt
        levels.append(level)
    return levels

def build_root(leaves: Sequence[bytes]) -> bytes:
    return _build_levels(leaves)[-1][0]

def build_proof(leaves: Sequence[bytes], index: int) -> InclusionProof:
    if not _is_int_not_bool(index): raise IndexOutOfRangeError('index must be int')
    levels = _build_levels(leaves)
    n = len(leaves)
    if index < 0 or index >= n: raise IndexOutOfRangeError('index out of range')
    steps=[]
    pos=index
    for lvl in range(len(levels)-1):
        cur_level = levels[lvl]
        sib_idx = pos ^ 1
        if sib_idx >= len(cur_level):
            sib_digest = cur_level[pos]
        else:
            sib_digest = cur_level[sib_idx]
        side = 'left' if sib_idx < pos else 'right'
        steps.append(ProofStep(sib_digest, side))
        pos //= 2
    return InclusionProof(leaf_index=index, leaf_count=n, steps=tuple(steps))

def _tree_height(n:int)->int:
    h=0
    while n>1:
        n=(n+1)//2; h+=1
    return h

def verify_proof(leaf: bytes, index: int, leaf_count: int, proof: InclusionProof, expected_root: bytes) -> bool:
    # 1
    if type(leaf) is not bytes: raise InvalidLeafError('leaf must be bytes')
    # 2
    if type(expected_root) is not bytes or len(expected_root)!=32: raise InvalidDigestError('expected_root must be 32 bytes')
    # 3
    if not isinstance(proof, InclusionProof): raise InvalidMetadataError('proof type')
    # 4,5 - metadata, with strict int check
    if not _is_int_not_bool(proof.leaf_index) or not _is_int_not_bool(proof.leaf_count):
        raise InvalidMetadataError('proof index/count type')
    if proof.leaf_index != index: raise InvalidMetadataError('index mismatch')
    if proof.leaf_count != leaf_count: raise InvalidMetadataError('leaf_count mismatch')
    # 6
    if not _is_int_not_bool(index) or not _is_int_not_bool(leaf_count):
        raise IndexOutOfRangeError('index/count type')
    if index < 0 or index >= leaf_count: raise IndexOutOfRangeError('index out of range')
    # 7
    for s in proof.steps:
        if type(s.sibling) is not bytes or len(s.sibling)!=32: raise InvalidDigestError('bad sibling')
        if s.side not in ('left','right'): raise InvalidSideError('bad side')
    # 8
    if len(proof.steps) != _tree_height(leaf_count): raise ProofLengthMismatchError('length mismatch')
    cur = leaf_hash(leaf)
    pos = index
    for step in proof.steps:
        if step.side == 'left':
            cur = node_hash(step.sibling, cur)
        else:
            cur = node_hash(cur, step.sibling)
        pos //= 2
    return cur == expected_root
