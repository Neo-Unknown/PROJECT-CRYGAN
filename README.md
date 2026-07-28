# Project Crygan

**A desktop application that records video and, at the same time, builds an independently verifiable, cryptographically signed record of that recording's integrity.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Project Crygan makes it possible to later answer two questions with strong technical evidence: *has this specific video file been altered since it was recorded*, and *if so, exactly which parts of it changed*.

It combines several well-established cryptographic and forensic techniques into a single layered pipeline: a rolling SHA-256 hash chain over every recorded frame, a Merkle tree for pinpointing altered frames, perceptual hashing to distinguish harmless re-encoding from genuine visual tampering, ECDSA digital signatures, AES-256-GCM encryption of evidence metadata, RFC 3161 trusted timestamping, and four independent, redundant storage mechanisms for the resulting evidence package.

---

## Table of Contents

- [Why](#why)
- [How It Works](#how-it-works)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Evidence Package Contents](#evidence-package-contents)
- [What This System Proves — and What It Doesn't](#what-this-system-proves--and-what-it-doesnt)
- [Known Limitations](#known-limitations)
- [Testing](#testing)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Why

Video is easy to fabricate or subtly edit, and easy to distrust as a result. Project Crygan gives a recording a cryptographic paper trail from the moment it's captured: every frame is hashed as it's written, the resulting chain is signed with a private key that never leaves the device, and the signed evidence is packaged and stored in multiple redundant ways so it can survive real-world handling of the file — sharing, copying, even partial corruption — without silently losing its provenance.

## How It Works

1. **Record.** As each frame is captured, it's fed into a rolling SHA-256 hash chain and, separately, into a Merkle tree of per-frame hashes. A 64-bit perceptual hash (dHash) is also computed per frame.
2. **Seal.** When recording stops, the final chain hash, Merkle root, camera/location/timestamp metadata, and the recorder's public key are assembled into a canonical JSON record and signed with an ECDSA (SECP384R1) private key.
3. **Encrypt & package.** The signed record is encrypted with AES-256-GCM (key derived via PBKDF2-HMAC-SHA256) and optionally timestamped by a public RFC 3161 Time-Stamp Authority.
4. **Store, redundantly.** The encrypted package is embedded directly in the video file (tail-appended plus an ISO-BMFF `uuid` box), mirrored to a companion `.crygan` sidecar file, summarized into a single-frame LSB steganographic reference PNG, and split into Reed–Solomon erasure-coded chunks spread across additional reference PNGs — plus a local perceptual-hash fingerprint kept in the app's own database as a last-resort fallback.
5. **Verify.** Given a video (and whichever of the above artifacts are available), the app recomputes the hash chain and Merkle tree from the file, checks the signature, cross-checks any embedded/companion/reference evidence, and — if the exact hashes don't match — uses perceptual hashing to classify each differing frame as *likely re-encoding* or *likely genuine content change*.

## Features

- **Tamper-evident recording** via a chained SHA-256 hash over every frame, sealed at the end of recording.
- **Frame-level tamper localization** using a Merkle tree, so verification can report *which* frames differ instead of just "integrity check failed."
- **Perceptual-hash classification (dHash)** to distinguish ordinary lossy re-encoding from an actual visual content change.
- **ECDSA (SECP384R1) signing** of all evidence metadata, with the private key encrypted at rest (AES-256-GCM, PBKDF2-derived key).
- **RFC 3161 trusted timestamping** against a public Time-Stamp Authority, independent of the recording device's own clock.
- **Four redundant, independent evidence storage mechanisms:**
  - Tail-appended payload embedded directly in the video file (plus an ISO-BMFF `uuid` box) — survives copying/sharing but not transcoding.
  - Portable companion `.crygan` sidecar file.
  - Single-frame LSB steganographic reference PNG (hash + signature only).
  - Reed–Solomon erasure-coded chunk reference PNGs — any subset of `STEGO_CHUNK_DATA_COUNT` out of the total chunks reconstructs the full package.
- **Local perceptual-hash registry** as an out-of-band fallback: if a video has no extractable embedded evidence at all (e.g. after transcoding), verification can fall back to fingerprint-matching it against this device's own recording history.
- **One-click evidence export**, bundling the video, companion file, LSB reference, chunk PNGs, and a manifest into a single self-contained folder.
- **PDF evidence reports** summarizing a verification run.
- **Approximate location tagging** (precise Windows Location Services when available, IP-based geolocation otherwise).
- **Light/dark/system theming**, background-threaded recording and verification so the UI never blocks.

## Architecture

The project intentionally lives in five files:

| File | Responsibility |
|---|---|
| `main.py` | Application bootstrap only. |
| `config.py` | Shared constants, filesystem paths, and tunable parameters. No dependencies on the other modules. |
| `crypto_core.py` | All cryptography: SHA-256/Merkle hashing, AES-256-GCM, ECDSA key management and signing, perceptual hashing, RFC 3161 timestamping, and the end-to-end verification pipeline (`VerificationEngine`). |
| `evidence_storage.py` | Storage and recovery of the encrypted evidence package across all four mechanisms described above, plus payload validation. |
| `project_UI.py` | Every GUI screen (record / verify / reports / settings) and their supporting logic: theming, the local SQLite evidence index, geolocation, camera capture orchestration, session state, and PDF report generation. |

Imports flow one direction only — `config.py` → `evidence_storage.py` → `crypto_core.py` → `project_UI.py` — so there is no circular dependency between them.

```
project-crygan/
├── main.py
├── config.py
├── crypto_core.py
├── evidence_storage.py
├── project_UI.py
├── requirements.txt
├── videos/            (created at runtime)
├── keys/              (created at runtime)
├── reports/           (created at runtime)
├── stego_refs/        (created at runtime)
└── evidence_exports/  (created at runtime)
```

> **Note on data location:** by design, all persistent data (keys, database, videos, reports) lives in ordinary sub-folders next to the application itself, rather than an OS-level app-data directory — so it's easy to browse to directly. This is documented in `config.py` as something that will need to change if the app is ever packaged as a frozen executable.

## Installation

**Requirements:** Python 3.9+

```bash
git clone https://github.com/<your-org>/project-crygan.git
cd project-crygan
pip install -r requirements.txt
python main.py
```

### Dependencies

Required: `PySide6`, `cryptography`, `opencv-python`, `requests`, `reportlab`, `numpy`.

Optional (the app runs fine without these — only the specific feature listed is unavailable):

| Package | Enables | Without it |
|---|---|---|
| `reedsolo` | Reed-Solomon erasure-coded chunk reference frames | Videos still record/verify normally; extra resilience against a corrupted primary payload is unavailable |
| `rfc3161ng` | RFC 3161 trusted timestamping | Recording/verification work exactly as before; the independent "hash existed by time T" attestation is silently skipped |
| `winsdk` (Windows only) | Precise Windows Location Services | Falls back to approximate IP-based geolocation |
| `pygrabber` (Windows only) | Real camera device names in the camera picker | Generic "Camera N" labels are used instead |

## Usage

1. Launch the app with `python main.py`.
2. **Record Video** — select a camera, start recording. On stop, the evidence pipeline runs automatically: hashing, signing, encryption, and storage across all available mechanisms.
3. **Verify Video** — select a video (and, optionally, a passphrase and any recovered reference artifacts) to run the full verification pipeline and see the result, including frame-level tamper localization if the hashes don't match.
4. **Evidence Reports** — browse past recordings and verification runs, and export a PDF report.
5. **Settings** — set/change the private key's protection password, toggle light/dark/system theme, and manage the optional "remember my password" convenience feature.

## Evidence Package Contents

Before any storage mechanism is applied, each recording assembles a single structured record, serialized to canonical JSON and signed:

- Application version, for long-term format compatibility.
- Location block (coordinates, resolved city/country, accuracy, source).
- Timestamp block (local time, UTC offset, full UTC start time).
- Frame hash chain block (algorithm, frame count, final chained hash, Merkle root, per-frame leaf hashes).
- Perceptual hash block (dHash algorithm + per-frame hashes), when available.
- Camera metadata.
- RFC 3161 timestamp block (TSA URL, algorithm, token), when a TSA was reachable.
- ECDSA signature over the canonical JSON of all of the above.
- The signer's public key (PEM), so a verifier never needs a separate keystore.

This structure is what gets encrypted (AES-256-GCM) before being written through the four storage mechanisms.

## What This System Proves — and What It Doesn't

Project Crygan can show that a specific video's frame data matches what was originally hashed and signed at record time, that the signing key was under this app's control, and — independently — that the resulting hash existed by a certain time according to a third-party clock. It can also localize *which* frames changed if verification fails.

It is **not** a hardware root of trust: it cannot prove what was physically in front of the camera, and it cannot prevent a sufficiently motivated attacker with access to the recording device itself from producing a convincingly signed but staged video. See `crypto_core.py` and the project report for the full threat model and cryptographic primitives used.

## Known Limitations

- Embedded/companion evidence does not survive re-encoding or transcoding of the video — this is structural, since transcoding rewrites the file's bytes from scratch. The local perceptual-hash registry exists specifically as a fallback for this case.
- Perceptual hashing provides *corroborating*, not cryptographic, evidence when classifying a mismatch as "re-encoded" vs. "altered."
- RFC 3161 verification trusts whatever signing certificate the TSA embeds in its response by default; it does not chain-verify to a trusted root CA unless a certificate is pinned via `TSA_CA_CERT_PATH`.
- The optional "remember my password" feature stores the session password locally, encrypted with a key that is itself stored unencrypted on disk — a deliberate convenience/security trade-off, disabled by default.
- No hardware root of trust; see above.

## Testing

The project report documents functional test coverage across unmodified recordings, trimmed video, visual (exposure/saturation) tampering, and tampering of a secondary evidence artifact (the LSB reference PNG) — confirming the system reliably distinguishes authentic recordings from altered ones, localizes altered frame indices, and degrades gracefully when individual evidence artifacts are lost, without ever falsely validating a tampered recording.

## Roadmap

- Genuine frame-level (bitstream) steganography as an alternative to the current tail-appended embedding technique, without changing the calling code in `evidence_storage.py`'s public API.
- OS-level app-data directory support for packaged/frozen builds.
- Hardware-backed key storage.

## Contributing

Issues and pull requests are welcome. Please keep the five-file module boundary and one-directional import structure (`config` → `evidence_storage` → `crypto_core` → `project_UI`) intact when contributing.

## License

Released under the [MIT License](LICENSE).
