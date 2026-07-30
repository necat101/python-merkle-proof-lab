import json, csv, sys
from merkle_proof import *
from MANIFEST import CASES, EXPECTED

def classify_exc(e):
    m = {EmptyTreeError:'empty_tree', InvalidLeafError:'invalid_leaf',
         IndexOutOfRangeError:'index_out_of_range', InvalidDigestError:'invalid_digest',
         InvalidSideError:'invalid_side', InvalidMetadataError:'invalid_metadata',
         ProofLengthMismatchError:'proof_length_mismatch'}
    for k,v in m.items():
        if isinstance(e,k): return v
    return type(e).__name__

rows=[]
case_ids=set()
for cid, leaves, idx, op, v_override, exp_class in CASES:
    if cid in case_ids: print(f"dup {cid}",file=sys.stderr); sys.exit(1)
    case_ids.add(cid)
    actual_class=None; actual_root=None; actual_steps=None
    verify_result=None; exc_type=None; passed=False; observation=""
    expected_root=None; expected_steps=None
    if cid in EXPECTED:
        expected_root=EXPECTED[cid]['root']
        expected_steps=EXPECTED[cid]['steps']
    try:
        if op=='proof':
            root=build_root(leaves)
            actual_root=root.hex()
            proof=build_proof(leaves, idx)
            actual_steps=[(s.sibling.hex(), s.side) for s in proof.steps]
            ok=verify_proof(leaves[idx], idx, len(leaves), proof, root)
            verify_result=bool(ok)
            actual_class='success' if ok else 'root_mismatch'
        elif op=='build_root':
            root=build_root(leaves); actual_root=root.hex(); actual_class='success'
        elif op=='build_proof':
            proof=build_proof(leaves, idx); actual_class='success'
        elif op.startswith('verify'):
            root=build_root(leaves); proof=build_proof(leaves, idx)
            leaf=leaves[idx]
            exp_root=root
            if op=='verify_tamper_leaf': leaf = v_override
            elif op=='verify_tamper_sibling':
                # flip a bit
                s0 = proof.steps[0]
                bad = bytes([s0.sibling[0]^1]) + s0.sibling[1:]
                from dataclasses import replace
                proof = InclusionProof(proof.leaf_index, proof.leaf_count, (ProofStep(bad, s0.side),)+proof.steps[1:])
            elif op=='verify_flip_side':
                s0 = proof.steps[0]
                flipped = 'left' if s0.side=='right' else 'right'
                proof = InclusionProof(proof.leaf_index, proof.leaf_count, (ProofStep(s0.sibling, flipped),)+proof.steps[1:])
            elif op=='verify_tamper_root':
                exp_root = bytes([root[0]^1])+root[1:]
            elif op=='verify_bad_digest_len':
                s0 = proof.steps[0]
                proof = InclusionProof(proof.leaf_index, proof.leaf_count, (ProofStep(s0.sibling[:31], s0.side),)+proof.steps[1:])
            elif op=='verify_bad_side':
                # construct invalid side via object.__new__
                s0 = proof.steps[0]
                bad_step = object.__new__(ProofStep)
                object.__setattr__(bad_step, 'sibling', s0.sibling)
                object.__setattr__(bad_step, 'side', 'up')
                proof = InclusionProof(proof.leaf_index, proof.leaf_count, (bad_step,)+proof.steps[1:])
            elif op=='verify_meta_index':
                proof = InclusionProof(proof.leaf_index ^ 1, proof.leaf_count, proof.steps)
            elif op=='verify_meta_count':
                proof = InclusionProof(proof.leaf_index, proof.leaf_count+1, proof.steps)
            elif op=='verify_missing_step':
                proof = InclusionProof(proof.leaf_index, proof.leaf_count, proof.steps[:-1])
            elif op=='verify_extra_step':
                proof = InclusionProof(proof.leaf_index, proof.leaf_count, proof.steps + (ProofStep(b'\x00'*32,'right'),))
            try:
                ok = verify_proof(leaf, idx, len(leaves), proof, exp_root)
                verify_result=bool(ok)
                actual_class='success' if ok else 'root_mismatch'
            except Exception as e:
                actual_class=classify_exc(e); exc_type=type(e).__name__
        else:
            actual_class='invalid_metadata'
    except Exception as e:
        if actual_class is None:
            actual_class=classify_exc(e); exc_type=type(e).__name__

    exp_root_hex = expected_root
    exp_steps = expected_steps
    passed = (actual_class == exp_class)
    if exp_root_hex: passed = passed and (actual_root == exp_root_hex)
    if exp_steps is not None: passed = passed and (actual_steps == exp_steps)
    if exp_class == 'success': passed = passed and (verify_result is True)
    if exp_class == 'root_mismatch': passed = passed and (verify_result is False)

    # record
    def leaves_repr(l):
        if isinstance(l, list) and all(type(x) is bytes for x in l):
            return [x.hex() for x in l]
        return f"malformed:{type(l).__name__}"
    rows.append({
        'case_id': cid,
        'classification': actual_class,
        'leaves': leaves_repr(leaves) if op!='build_root_nonbytes' else 'malformed:non_bytes',
        'index': idx if op not in ('build_root','build_root_nonbytes') else None,
        'expected_root_hex': exp_root_hex,
        'actual_root_hex': actual_root,
        'expected_proof_steps': exp_steps,
        'actual_proof_steps': actual_steps,
        'expected_outcome': exp_class,
        'actual_outcome': actual_class,
        'verification_result': verify_result,
        'exception_type': exc_type,
        'observation': observation,
        'passed': passed
    })
    if not passed:
        print(f"FAIL {cid} expected {exp_class} got {actual_class}", file=sys.stderr)

# totals
from collections import Counter
totals = Counter(r['classification'] for r in rows)
print(f"cases={len(rows)} passed={sum(1 for r in rows if r['passed'])}")
for k in ['success','empty_tree','invalid_leaf','index_out_of_range','invalid_digest','invalid_side','invalid_metadata','proof_length_mismatch','root_mismatch']:
    print(f"  {k}: {totals.get(k,0)}")

# write json
out_json = {'cases': rows, 'totals': dict(totals), 'case_count': len(rows)}
with open('results.json','w',newline='\n') as f:
    json.dump(out_json, f, sort_keys=True, separators=(',',':'))
    f.write('\n')

# csv
cols=['case_id','classification','leaves','index','expected_root_hex','actual_root_hex','expected_proof_steps','actual_proof_steps','expected_outcome','actual_outcome','verification_result','exception_type','observation','passed']
with open('results.csv','w',newline='\n') as f:
    w=csv.writer(f, quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
    w.writerow(cols)
    for r in rows:
        w.writerow([json.dumps(r[c], sort_keys=True, separators=(',',':')) if isinstance(r[c], (list,dict)) else r[c] for c in cols])

# RESULTS.md
with open('RESULTS.md','w',newline='\n') as f:
    f.write('# Results\n\n')
    f.write(f"Cases: {len(rows)}\n\n")
    f.write('| classification | count |\n|---|---|\n')
    for k in ['success','empty_tree','invalid_leaf','index_out_of_range','invalid_digest','invalid_side','invalid_metadata','proof_length_mismatch','root_mismatch']:
        f.write(f"| {k} | {totals.get(k,0)} |\n")
    f.write('\n| case_id | classification | passed |\n|---|---|---|\n')
    for r in rows:
        f.write(f"| {r['case_id']} | {r['classification']} | {r['passed']} |\n")

if any(not r['passed'] for r in rows):
    sys.exit(2)
