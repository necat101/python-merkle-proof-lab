import unittest, hashlib
from merkle_proof import leaf_hash, node_hash, build_root, build_proof, verify_proof, ProofStep, InclusionProof, InvalidLeafError, InvalidDigestError, InvalidSideError, InvalidMetadataError, ProofLengthMismatchError, IndexOutOfRangeError

def lh_manual(data: bytes) -> bytes:
    return hashlib.sha256(b'\x00' + len(data).to_bytes(4,'big') + data).digest()
def nh_manual(l: bytes, r: bytes) -> bytes:
    return hashlib.sha256(b'\x01' + l + r).digest()

class TestMerkle(unittest.TestCase):
    def test_leaf_hash_domain(self):
        h = leaf_hash(b'a')
        exp = hashlib.sha256(b'\x00\x00\x00\x00\x01a').digest()
        self.assertEqual(h, exp)
        self.assertEqual(len(h),32)
    def test_node_hash_domain(self):
        l = b'\x11'*32; r = b'\x22'*32
        h = node_hash(l,r)
        self.assertEqual(h, hashlib.sha256(b'\x01'+l+r).digest())
    def test_length_prefix(self):
        h0 = leaf_hash(b'')
        self.assertEqual(h0, hashlib.sha256(b'\x00\x00\x00\x00\x00').digest())
        h1 = leaf_hash(b'\x00\x00foo')
        self.assertEqual(h1, lh_manual(b'\x00\x00foo'))
    def test_domain_separation(self):
        l = leaf_hash(b'test')
        n = nh_manual(b'\x00'*32, b'\x00'*32)
        self.assertNotEqual(l, n)
    def test_root_one(self):
        root = build_root([b'a'])
        self.assertEqual(root, lh_manual(b'a'))
    def test_root_two(self):
        a = lh_manual(b'a'); b = lh_manual(b'b')
        exp = nh_manual(a,b)
        self.assertEqual(build_root([b'a',b'b']), exp)
    def test_root_three_odd(self):
        a=lh_manual(b'a'); b=lh_manual(b'b'); c=lh_manual(b'c')
        n1=nh_manual(a,b); n2=nh_manual(c,c)
        exp=nh_manual(n1,n2)
        self.assertEqual(build_root([b'a',b'b',b'c']), exp)
    def test_root_four(self):
        leaves=[b'a',b'b',b'c',b'd']
        hs=[lh_manual(x) for x in leaves]
        n1=nh_manual(hs[0],hs[1]); n2=nh_manual(hs[2],hs[3])
        exp=nh_manual(n1,n2)
        self.assertEqual(build_root(leaves), exp)
    def test_root_five(self):
        leaves=[b'a',b'b',b'c',b'd',b'e']
        hs=[lh_manual(x) for x in leaves]
        # level1: ab, cd, ee, ee
        l1=[nh_manual(hs[0],hs[1]), nh_manual(hs[2],hs[3]), nh_manual(hs[4],hs[4]), nh_manual(hs[4],hs[4])]
        l2=[nh_manual(l1[0],l1[1]), nh_manual(l1[2],l1[3])]
        exp=nh_manual(l2[0],l2[1])
        self.assertEqual(build_root(leaves), exp)
    def test_order_sensitivity(self):
        r1=build_root([b'a',b'b']); r2=build_root([b'b',b'a'])
        self.assertNotEqual(r1,r2)
    def test_duplicate_value_positional(self):
        leaves=[b'x',b'y',b'x']
        p0=build_proof(leaves,0); p2=build_proof(leaves,2)
        self.assertNotEqual(p0.steps, p2.steps)
        root=build_root(leaves)
        self.assertTrue(verify_proof(b'x',0,3,p0,root))
        self.assertTrue(verify_proof(b'x',2,3,p2,root))
    def test_left_right_orientation(self):
        leaves=[b'a',b'b']
        p=build_proof(leaves,0)
        self.assertEqual(p.steps[0].side,'right')
        root=build_root(leaves)
        self.assertTrue(verify_proof(b'a',0,2,p,root))
        # flipped
        bad = InclusionProof(p.leaf_index,p.leaf_count,(ProofStep(p.steps[0].sibling,'left'),))
        self.assertFalse(verify_proof(b'a',0,2,bad,root))
    def test_odd_duplication(self):
        p=build_proof([b'a',b'b',b'c'],2)
        self.assertEqual(p.steps[0].sibling, lh_manual(b'c'))
        self.assertEqual(p.steps[0].side,'right')
    def test_tamper_leaf(self):
        leaves=[b'a',b'b']; p=build_proof(leaves,0); root=build_root(leaves)
        self.assertFalse(verify_proof(b'A',0,2,p,root))
    def test_tamper_sibling(self):
        leaves=[b'a',b'b']; p=build_proof(leaves,0); root=build_root(leaves)
        bad_sib = bytes([p.steps[0].sibling[0]^1])+p.steps[0].sibling[1:]
        bad = InclusionProof(0,2,(ProofStep(bad_sib,'right'),))
        self.assertFalse(verify_proof(b'a',0,2,bad,root))
    def test_tamper_root(self):
        leaves=[b'a',b'b']; p=build_proof(leaves,0); root=build_root(leaves)
        bad_root = bytes([root[0]^1])+root[1:]
        self.assertFalse(verify_proof(b'a',0,2,p,bad_root))
    def test_proof_length_calc(self):
        def h(n):
            c=0
            while n>1: n=(n+1)//2; c+=1
            return c
        for n,exp in [(1,0),(2,1),(3,2),(4,2),(5,3),(8,3),(16,4)]:
            self.assertEqual(h(n),exp)
            if n>1:
                p=build_proof([b'x']*n,0)
                self.assertEqual(len(p.steps),exp)
    def test_invalid_digest(self):
        leaves=[b'a',b'b']; p=build_proof(leaves,0); root=build_root(leaves)
        bad = InclusionProof(0,2,(ProofStep(b'\x00'*31,'right'),))
        with self.assertRaises(InvalidDigestError): verify_proof(b'a',0,2,bad,root)
    def test_invalid_side(self):
        leaves=[b'a',b'b']; p=build_proof(leaves,0); root=build_root(leaves)
        bad_step = object.__new__(ProofStep)
        object.__setattr__(bad_step,'sibling',p.steps[0].sibling)
        object.__setattr__(bad_step,'side','up')
        bad = InclusionProof(0,2,(bad_step,))
        with self.assertRaises(InvalidSideError): verify_proof(b'a',0,2,bad,root)
    def test_metadata_mismatch(self):
        leaves=[b'a',b'b']; p=build_proof(leaves,0); root=build_root(leaves)
        bad = InclusionProof(1,2,p.steps)
        with self.assertRaises(InvalidMetadataError): verify_proof(b'a',0,2,bad,root)
        bad2 = InclusionProof(0,3,p.steps)
        with self.assertRaises(InvalidMetadataError): verify_proof(b'a',0,2,bad2,root)
    def test_missing_extra_step(self):
        leaves=[b'a',b'b',b'c',b'd']; p=build_proof(leaves,0); root=build_root(leaves)
        short = InclusionProof(0,4,p.steps[:-1])
        with self.assertRaises(ProofLengthMismatchError): verify_proof(b'a',0,4,short,root)
        long = InclusionProof(0,2, build_proof([b'a',b'b'],0).steps + (ProofStep(b'\x00'*32,'right'),))
        with self.assertRaises(ProofLengthMismatchError): verify_proof(b'a',0,2,long,build_root([b'a',b'b']))
    def test_caller_input_unchanged(self):
        leaves=[b'a',b'b']; orig=leaves.copy()
        build_root(leaves); build_proof(leaves,0)
        self.assertEqual(leaves, orig)
        p=build_proof(leaves,0)
        root=build_root(leaves)
        verify_proof(b'a',0,2,p,root)
        self.assertEqual(p.leaf_index,0)
    def test_reject_non_bytes(self):
        with self.assertRaises(InvalidLeafError): build_root([b'a','a'])
        with self.assertRaises(InvalidLeafError): build_root([bytearray(b'a')])
        with self.assertRaises(InvalidLeafError): leaf_hash("a")  # type: ignore
    def test_bool_not_int(self):
        leaves=[b'a',b'b']
        with self.assertRaises(IndexOutOfRangeError): build_proof(leaves, True)  # type: ignore
        p=build_proof(leaves,0); root=build_root(leaves)
        with self.assertRaises((IndexOutOfRangeError, InvalidMetadataError)): verify_proof(b'a', True, 2, p, root)  # type: ignore

if __name__=='__main__': unittest.main()
