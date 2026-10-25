#!/bin/bash -eu
# Dependencies come from the hash-locked requirements.txt; nothing unpinned is downloaded.
python3 -m pip install --require-hashes -r requirements.txt
python3 -m pip wheel --no-deps --no-build-isolation -w /tmp/wheel .
python3 -m pip install --no-deps /tmp/wheel/*.whl
for fuzzer in fuzz/fuzz_*.py; do
  compile_python_fuzzer "${fuzzer}"
done
