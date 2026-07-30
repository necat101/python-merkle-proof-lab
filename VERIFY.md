# VERIFY – python-merkle-proof-lab (rev2)

Implementation commit: b88a20f616fa14ee54f61408ff1953d8b2b00ea5
Repo: https://github.com/necat101/python-merkle-proof-lab
Branch: main

This VERIFY.md supersedes the VERIFY.md at 06e410c8276fdef40431f7a001c79cff0f239e48 (which verified 9a32fcf304b06a960300831ea5c2a81729f8c666).

## Clean-clone verification transcript

Commands run in a fresh directory, detached at the implementation commit.

```
$ git clone https://github.com/necat101/python-merkle-proof-lab.git merkle_verify2
Cloning into 'merkle_verify2'...
exit:0

$ cd merkle_verify2
$ git rev-parse HEAD
b88a20f616fa14ee54f61408ff1953d8b2b00ea5
exit:0

$ git checkout --detach b88a20f616fa14ee54f61408ff1953d8b2b00ea5
HEAD is now at b88a20f merkle-proof: fix manifest input provenance (c14), tighten independent tests
exit:0

$ python3 --version
Python 3.12.3
exit:0

$ python3 -m compileall merkle_proof
Listing 'merkle_proof'...
Compiling 'merkle_proof/__init__.py'...
exit:0

$ python3 run_lab.py
cases=26 passed=26
  success: 12
  empty_tree: 1
  invalid_leaf: 1
  index_out_of_range: 2
  invalid_digest: 1
  invalid_side: 1
  invalid_metadata: 2
  proof_length_mismatch: 2
  root_mismatch: 4
exit:0

$ python3 -m unittest tests.test_merkle_independent -v
test_bool_not_int ... ok
test_caller_input_unchanged ... ok
test_domain_separation ... ok
test_duplicate_value_positional ... ok
test_invalid_digest ... ok
test_invalid_side ... ok
test_leaf_hash_domain ... ok
test_left_right_orientation ... ok
test_length_prefix ... ok
test_metadata_mismatch ... ok
test_missing_extra_step ... ok
test_node_hash_domain ... ok
test_odd_duplication ... ok
test_order_sensitivity ... ok
test_proof_length_calc ... ok
test_reject_non_bytes ... ok
test_root_five ... ok
test_root_four ... ok
test_root_one ... ok
test_root_three_odd ... ok
test_root_two ... ok
test_tamper_leaf ... ok
test_tamper_root ... ok
test_tamper_sibling ... ok
----------------------------------------------------------------------
Ran 24 tests in 0.008s
OK
exit:0
```

## Artifact comparison

Regenerated in the clean clone, compared byte-for-byte against committed files (git status clean confirms identity):

```
$ sha256sum results.json results.csv RESULTS.md
67ccec006f39e76676dba0961cd338f27db7e721df1c57c86cc67ae79efa3acd  results.json
100d83791bae717ebd7fb5e55b72e2649fb9fa42550c43047296621ccd6ee8fd  results.csv
3968a21235367d7c6ceaa6a0eaa3a46e981c8c75c97edab883718f6887576dc3  RESULTS.md
exit:0

$ git status --short
<no output>
exit:0
```

Committed artifacts are byte-identical to regenerated artifacts.

## Summary

- git rev-parse HEAD: b88a20f616fa14ee54f61408ff1953d8b2b00ea5
- Python: Python 3.12.3
- compile: exit 0
- runner: exit 0, cases=26 passed=26
  - success: 12
  - empty_tree: 1
  - invalid_leaf: 1
  - index_out_of_range: 2
  - invalid_digest: 1
  - invalid_side: 1
  - invalid_metadata: 2
  - proof_length_mismatch: 2
  - root_mismatch: 4
- unittest: 24 tests, OK, exit 0
- results.json: byte-identical (sha256 67ccec006f39e76676dba0961cd338f27db7e721df1c57c86cc67ae79efa3acd)
- results.csv: byte-identical (sha256 100d83791bae717ebd7fb5e55b72e2649fb9fa42550c43047296621ccd6ee8fd)
- RESULTS.md: byte-identical (sha256 3968a21235367d7c6ceaa6a0eaa3a46e981c8c75c97edab883718f6887576dc3)
- working tree: clean
- failures: 0
- skips: 0
- wall time: ~0.12s

## Changes from v1 (9a32fcf)

- MANIFEST c14: executed input now comes directly from committed manifest (`[b'a', "a"]`), removed build_root_nonbytes runner hard-code
- test_bool_not_int: asserts exact documented error precedence (IndexOutOfRangeError / InvalidMetadataError), no longer accepts either/or
- test_reject_non_bytes: added explicit memoryview rejection
- test_caller_input_unchanged: expanded to full proof-object immutability (steps tuple identity, sibling digest identity, frozen dataclass mutation raises)
