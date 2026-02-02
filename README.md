# Artifact README

This artifact package enables end-to-end reproduction of the results reported in our paper and provides sufficient materials to (i) run LEMUR-Fuzz on the evaluated targets, (ii) reproduce all research-question (RQ) experiments in a controlled environment, and (iii) generate the protocol-specific components with the help of LLMs.

## Repository layout

This artifact consists of two local subdirectories and one external package link (each with its own detailed README):

- `lemur-fuzz/` — **LEMUR-Fuzz**: an AFLNet-compatible protocol fuzzer extended with a semantic-aware mutation stage.
- `components-generation/` — **Protocol-specific components generation**: the pipeline and utilities to synthesize and validate protocol-specific components (message templates, parser/reassembler, mutators, fixers).
- **Pre-built Docker Images (external link)** — **Reproducible experiments**: pre-built Docker images plus execution and analysis scripts for all RQs (recommended for reviewers). See: [DOCKER_LINK](https://zenodo.org/records/18375204?preview=1&token=eyJhbGciOiJIUzUxMiJ9.eyJpZCI6IjZkOTgwZTg5LTc3OGMtNDg1ZS1hMjZkLTgwY2NmNmQ2Yjg5NSIsImRhdGEiOnt9LCJyYW5kb20iOiI4ZmIzYzcwNDQ1YTBlOTUyNzAzZDUxNWQwZjA1NmMzYiJ9.Tiz9v4fArdx3_ihLmBerlhrEEQblesXw1IR3ModvfUB4fk2cciT59wmXITHDPXCZCgkiX6FlAwmAp5sCX51WUw)

> For step-by-step instructions, please consult the README in each local directory and the Docker package documentation linked above.

---

## Getting started (recommended)

For the fastest and most reproducible evaluation, use the **pre-built Docker images** and the provided RQ scripts:

1. Load the provided Docker images into your local Docker daemon.
2. Run the corresponding `RQ*.sh` execution scripts to produce standardized `.tar.gz` result artifacts.
3. Run the analysis scripts to regenerate the figures/tables reported in the paper.

This workflow eliminates most host-side dependency issues and ensures consistent target versions and runtime configurations across runs.

---

## 1) `lemur-fuzz/` — LEMUR-Fuzz

**LEMUR-Fuzz** enhances AFLNet with **protocol-specific, LLM-generated semantic-aware components**, while preserving the original AFLNet fuzzing workflow. It integrates a semantic-aware mutation stage into the standard pipeline:

- parse seed → field-level mutate → constraint fix → reassemble → send to server

### Scope and key properties
- **AFLNet-compatible**: LEMUR-Fuzz follows AFLNet’s build and execution style, and existing AFLNet scripts can typically be reused with minimal changes.
- **Protocol-specific once-per-protocol generation**: protocol components are synthesized once per protocol (from specifications) and then reused during fuzzing; fuzzing itself does not require online LLM calls.
- **Constraint-aware repair**: fixers repair cross-field dependencies after mutation to improve acceptance and deeper execution.

### Supported protocols (as shipped in the artifact)
LEMUR-Fuzz includes protocol-specific components for:
- MQTT 5.0 (e.g., Mosquitto, NanoMQ)
- RTSP (e.g., live555)
- SIP (e.g., Kamailio)
- FTP (e.g., ProFTPD, Pure-FTPd)
- SMTP (e.g., Exim)
- DTLS 1.2 (e.g., TinyDTLS)

### Example usage
The `lemur-fuzz/README.md` provides an AFLNet-style example command (e.g., Mosquitto/MQTT) and build guidance.

### Ablation controls
LEMUR-Fuzz exposes two environment variables for ablation studies and debugging:
- `FIXER_OFF=1`: disable constraint fixing after semantic mutation.
- `HAVOC_OFF=1`: disable AFLNet’s original byte-level havoc/splicing mutations (semantic-only mode).

---

## 2) Pre-built Docker Images (external link) — Reproducible experiments (Docker)

This linked Zenodo package contains everything required to reproduce the experiments in the paper **without rebuilding environments from scratch**:

- Two pre-built Docker image bundles (e.g., `Docker_Images_1.zip`, `Docker_Images_2.zip`) containing protocol-specific environments (targets, fuzzers, harnesses, and dependencies).
- `Execution_Scripts.tar.gz`: scripts that launch containers, run fuzzing campaigns, and export standardized `.tar.gz` artifacts.
- `Analysis_Scripts.tar.gz`: scripts that extract results from `.tar.gz` artifacts and regenerate the plots.

### Research questions and scripts
We evaluate 4 RQs; since RQ1 includes both coverage and crash endpoints, it is split into two scripts. In total, there are 5 execution scripts:
- RQ1 (Branch Coverage): `RQ1_Coverage.sh`
- RQ1 (Crashes/Bug Finding): `RQ1_Crash.sh`
- RQ2 (Design Choice / Overlap): `RQ2_Venn_Diagram.sh`
- RQ3 (Ablation Study): `RQ3_Ablation_Studies.sh`
- RQ4 (Message Validity): `RQ4_Success_Ratio.sh`

### Workflow
The Docker workflow is intentionally divided into two stages:
1. **Run experiments** (`run_experiments`): execute `RQ*.sh` to run fuzzing in containers and export `.tar.gz` outputs.
2. **Output analysis** (`output_analysis`): analyze exported `.tar.gz` outputs and regenerate figures.

### Requirements
- Docker installed and running
- Sufficient storage (≥ 100 GB recommended for full reproduction)

### Link to the reproducibility package
Docker images and scripts are provided here:
- [DOCKER_LINK](https://zenodo.org/records/18375204?preview=1&token=eyJhbGciOiJIUzUxMiJ9.eyJpZCI6IjZkOTgwZTg5LTc3OGMtNDg1ZS1hMjZkLTgwY2NmNmQ2Yjg5NSIsImRhdGEiOnt9LCJyYW5kb20iOiI4ZmIzYzcwNDQ1YTBlOTUyNzAzZDUxNWQwZjA1NmMzYiJ9.Tiz9v4fArdx3_ihLmBerlhrEEQblesXw1IR3ModvfUB4fk2cciT59wmXITHDPXCZCgkiX6FlAwmAp5sCX51WUw)

Please refer to `README.md` in the Zenodo record for exact commands, arguments, and output layout.

---

## 3) `components-generation/` — A pipeline to generate protocol-specific components with LLM-assistance

This directory provides the pipeline used to synthesize **protocol-specific components** once per protocol from protocol specifications, as well as targeted validation procedures to ensure correctness.

### Generated components (per protocol)
- **Message templates** (structured message representations)
- **Parser / reassembler** (bytes ↔ structured packets)
- **Semantic-aware field mutators**
- **Constraint fixers** (repairing cross-field dependencies after mutation)

### Output locations
Generated C artifacts are placed under:
- `llm/<proto>/<proto>_packets.h`       # message templates
- `llm/<proto>/<proto>_packets.c`       # message templates and a print function to output structured data
- `llm/<proto>/<proto>_parser.c`        # a parser to deserialize byte strings to structured data
- `llm/<proto>/<proto>_reassembler.c`   # a parser to serialize structured data to byte strings
- `llm/<proto>/<proto>_mutators.c`      # field-level semantic-aware mutators
- `llm/<proto>/<proto>_fixers.c`        # constraint fixers

Fixer sanity test registries are generated under:
- `tests/fixer_sanity/<proto>_fixer_registry.c`
- `tests/fixer_sanity/<proto>_fixer_sanity_tests.c`

### Validation procedures (targeted checks)
- **Templates**: manually inspected for consistency with the specification.
- **Parser + reassembler**: validated via metamorphic parse–reassemble testing.
- **Mutators**: checked for parseability preservation under mutation.
- **Fixers**: validated using constraint-violating test cases.

These checks can be run via scripts in `tests/`, for example:
- `./tests/PR_mr/mr_test.sh <proto> <seed_dir>`
- `./tests/mutator_sanity/run_mutator_sanity.sh <proto> <seed_dir>`
- `./tests/fixer_sanity/run_fixer_sanity.sh <proto>`

### Human-in-the-loop policy
If a check fails, the system reports diagnostics and the issue is resolved manually.

Please refer to `components-generation/README.md` for environment setup, interactive pipeline usage, caching/logging, and troubleshooting.
