#!/bin/bash -eu
# Dependencies come from the hash-locked requirements.txt; nothing unpinned is downloaded.
python3 -m pip install --require-hashes -r requirements.txt
python3 -m pip install --no-deps --no-build-isolation .
for fuzzer in fuzz/fuzz_*.py; do
  compile_python_fuzzer "${fuzzer}"
done
