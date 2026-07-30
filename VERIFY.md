# VERIFY

Implementation commit: 9a32fcf304b06a960300831ea5c2a81729f8c666
Branch: main
Repo: https://github.com/necat101/python-merkle-proof-lab

Clean clone verification:
- git rev-parse HEAD: 9a32fcf304b06a960300831ea5c2a81729f8c666
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
- results.json: byte-identical (sha256 328aec5f3c27ac05f52a52556cf98dbb53b668648a0a2758480937e897673aa6)
- results.csv: byte-identical (sha256 c6631b68bb2235cec4b271eb7034a3368327a05d47c9a324649ff4d516cdc138)
- RESULTS.md: byte-identical (sha256 3968a21235367d7c6ceaa6a0eaa3a46e981c8c75c97edab883718f6887576dc3)
- working tree: clean
- failures: 0
- skips: 0
- wall time: ~0.12s

Documentation commit will be direct descendant changing only this file.
