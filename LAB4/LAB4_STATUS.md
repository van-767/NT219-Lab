# LAB4 Completion Checklist

This checklist reflects the current repository state.

## Task 1 - Hash implementation

Status: code is present, needs final build/run evidence.

Implemented:

- SHA-224, SHA-256, SHA-384, SHA-512.
- SHA3-224, SHA3-256, SHA3-384, SHA3-512.
- SHAKE128 and SHAKE256 with configurable output length.
- Text input and streamed file input.
- CLI modes: `digest`, `kat`, `bench`.
- GUI wrapper through the C API.

Remaining evidence to produce:

- Build `hashtool`.
- Run digest examples for text and file input.
- Save screenshots or terminal output for the report.

## Task 2 - Known-answer tests

Status: KAT set is now complete for the implemented hash algorithms.

Current KAT file:

- `task1_hashing/tests/kat_vectors.json`
- 1662 one-shot test cases.
- SHA-2 and SHA-3 fixed-output vectors converted from official NIST CAVP files.
- SHAKE vectors included for several output lengths.

Run:

```bash
hashtool kat --kat tests/kat_vectors.json
```

Expected:

```text
Summary: 1662 passed, 0 failed, 1662 total.
```

Remaining evidence to produce:

- Run KAT after building.
- Save the final summary line into the report.

## Task 3 - Hash benchmark

Status: benchmark code and scripts are ready, but benchmark logs still need to be generated.

Scripts:

- Windows: `task1_hashing/scripts/run_bench.ps1`
- Windows wrapper: `task1_hashing/scripts/run_bench.bat`
- Linux: `task1_hashing/scripts/run_bench.sh`

Coverage:

- 10 algorithms: SHA-2, SHA-3, SHAKE128, SHAKE256.
- 4 message sizes: 1 KiB, 64 KiB, 1 MiB, 100 MiB.
- CSV logs with mean, median, standard deviation, 95 percent CI, throughput.

Run practical benchmark:

```powershell
.\scripts\run_bench.ps1
```

Run strict benchmark:

```powershell
.\scripts\run_bench.ps1 -FullSpec
```

Remaining evidence to produce:

- Generate `logs/windows/*.csv` or `logs/linux/*.csv`.
- Put benchmark table into the report.
- State CPU, OS, compiler, Crypto++ version/path, and benchmark parameters.

## Task 4 - Hash attacks

Status: attack materials are present.

Implemented:

- MD5 chosen-prefix collision demo:
  - `attacks/md5_collision/README.md`
  - `collision1.cpp`
  - `collision2.cpp`
  - `md5_result.txt`
  - `sha256_result.txt`
  - `diff_result.txt`

- Length-extension attack:
  - `attacks/length_extension/README.md`
  - `result.txt`

Remaining evidence to produce:

- Confirm the attack commands still reproduce the recorded outputs.
- Add the command output and short security explanation to the report.

## Final items before submission

- Build the project successfully on the target OS.
- Run KAT and keep the summary.
- Run benchmark and keep CSV logs.
- Add screenshots or copied terminal output for digest, KAT, benchmark, and attacks.
- Ensure the final report maps each task to source files, commands, and results.
