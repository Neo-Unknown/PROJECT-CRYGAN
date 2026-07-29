<div align="center">

# 🛡️ PROJECT CRYGAN

### **A Multi-Layer Digital Video Integrity Verification & Tamper Analysis Framework**

<p align="center">
An open-source forensic framework for secure video recording, cryptographic evidence generation,
multi-layer integrity verification, redundant evidence recovery, and comprehensive forensic reporting.
</p>

---

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![OpenCV](https://img.shields.io/badge/OpenCV-Computer%20Vision-green?logo=opencv)
![PySide6](https://img.shields.io/badge/PySide6-GUI-41CD52?logo=qt)
![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?logo=sqlite)
![License](https://img.shields.io/badge/License-MIT-orange)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)
![Status](https://img.shields.io/badge/Status-Active-success)
![Version](https://img.shields.io/badge/Version-1.0-red)
</div>

---

# 📖 Overview

**Project Crygan** is a digital forensic framework designed to preserve the authenticity and integrity of recorded video evidence through a **multi-layer cryptographic verification architecture**.

Unlike traditional video recorders that merely capture footage, Project Crygan continuously generates forensic metadata during recording, cryptographically protects it, stores it redundantly across multiple evidence layers, and later verifies the authenticity of a submitted recording while providing a detailed forensic integrity report.

The framework is designed for environments where digital video authenticity is critical, including:

- Digital Forensics
- Law Enforcement
- Incident Documentation
- Legal Evidence Preservation
- Research
- Academic Demonstrations
- Enterprise Compliance
- Chain-of-Custody Verification

---

# ✨ Key Highlights

✔ Secure video recording

✔ Automatic evidence generation

✔ SHA-256 frame hash chaining

✔ Merkle Tree frame commitment

✔ AES-256-GCM encrypted evidence package

✔ ECDSA digital signatures

✔ RFC 3161 trusted timestamp integration

✔ Multi-layer redundant evidence storage

✔ Reed–Solomon based evidence recovery

✔ Companion `.crygan` evidence package

✔ LSB reference PNG generation

✔ Evidence export bundles

✔ UUID-based evidence discovery

✔ Multi-layer integrity verification

✔ Tamper localization

✔ Re-encoding vs visual modification classification

✔ Human-readable forensic verification reports

---

# 🎯 Project Objectives

Project Crygan aims to solve one of the biggest challenges in digital forensics:

> **"How can we prove that a video has not been altered after recording?"**

The framework addresses this problem by:

- Cryptographically protecting recorded evidence
- Detecting modifications made after recording
- Identifying altered frame regions
- Distinguishing re-encoding from probable visual modification
- Preserving evidence through redundant storage mechanisms
- Supporting independent forensic verification

---

# 🚀 Core Features

| Feature | Description |
|----------|-------------|
| 🎥 Secure Recording | Captures video while generating forensic metadata |
| 🔐 AES-256 Encryption | Protects evidence package using authenticated encryption |
| ✍️ Digital Signature | ECDSA signatures ensure evidence authenticity |
| 🔗 Frame Hash Chain | Detects inserted, removed, or modified frames |
| 🌳 Merkle Tree | Localizes frame-level integrity differences |
| 🧠 Perceptual Hash Analysis | Helps distinguish recompression from probable visual edits |
| 🕒 Trusted Timestamp | RFC 3161 timestamp for independent temporal proof |
| 📦 Companion Evidence Package | Portable `.crygan` forensic evidence file |
| 🖼️ LSB Reference PNG | Independent corroborative integrity reference |
| 🧩 Reed–Solomon Recovery | Evidence reconstruction from distributed PNG chunks |
| 🗃 SQLite Registry | Local evidence discovery and recovery support |
| 📑 PDF Verification Reports | Detailed forensic verification summaries |
| 📤 Evidence Export | Portable investigation bundles |

---

# 🏗 System Architecture

Project Crygan follows a layered modular architecture.

```
                User Interface
                     │
                     ▼
          Recording / Verification
                     │
                     ▼
           Cryptographic Engine
                     │
                     ▼
      Multi-Layer Evidence Storage
                     │
                     ▼
          Verification Engine
                     │
                     ▼
          Forensic Report Generator
```

The system separates recording, cryptography, evidence storage, verification, and reporting into independent modules, making the framework extensible and maintainable.

---

# 📂 Repository Structure

```text
PROJECT-CRYGAN/
│
├── config.py                 # Global configuration and constants
├── crypto_core.py            # Cryptographic operations
├── evidence_storage.py       # Evidence packaging & storage
├── project_UI.py             # PySide6 graphical interface
├── main.py                   # Application entry point
├── requirements.txt
```

---

# ⚙ Technology Stack

| Category | Technologies |
|----------|--------------|
| Programming Language | Python 3.10+ |
| GUI Framework | PySide6 |
| Computer Vision | OpenCV |
| Cryptography | cryptography |
| Image Processing | Pillow |
| Numerical Computing | NumPy |
| Database | SQLite3 |
| Error Correction | Reed–Solomon |
| Hashing | SHA-256 |
| Encryption | AES-256-GCM |
| Digital Signature | ECDSA (SECP384R1) |
| Timestamping | RFC 3161 TSA |
| Packaging | JSON + Binary Evidence Package |

---

# 🔐 Cryptographic Design

Project Crygan combines multiple cryptographic primitives to provide layered integrity guarantees.

| Primitive | Purpose |
|-----------|----------|
| SHA-256 | Frame hash chain generation |
| Merkle Tree | Frame commitment & localization |
| AES-256-GCM | Evidence package encryption |
| PBKDF2 | Encryption key derivation |
| ECDSA (SECP384R1) | Digital signature generation |
| RFC 3161 | Trusted timestamping |
| UUID | Evidence identification |

Each primitive contributes a specific role, creating multiple independent layers of evidence verification instead of relying on a single integrity mechanism.

---

# 🖥 Supported Platform

| Platform | Status |
|-----------|--------|
| Windows | ✅ Fully Supported |
| Linux | ⚠ Experimental |
| macOS | ⚠ Experimental |

---

# 📥 Installation

Clone the repository:

```bash
git clone https://github.com/Neo-Unknown/PROJECT-CRYGAN.git

cd PROJECT-CRYGAN
```

Create a virtual environment (recommended):

```bash
python -m venv venv
```

Activate it.

Windows

```bash
venv\Scripts\activate
```

Linux/macOS

```bash
source venv/bin/activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

---

# ▶ Running Project Crygan

Launch the application:

```bash
python main.py
```

The graphical interface will allow you to:

- Record secure videos
- Verify recorded evidence
- Export evidence bundles
- Generate forensic reports
- Manage application settings

---

# 🔄 Complete Project Workflow

Project Crygan follows a complete forensic evidence lifecycle beginning from secure video acquisition and ending with comprehensive integrity verification and forensic reporting.

```text
                    Record Video
                         │
                         ▼
            Generate Frame Integrity Data
                         │
                         ▼
          Build Cryptographic Evidence Package
                         │
                         ▼
             Encrypt & Digitally Sign Evidence
                         │
                         ▼
          Store Across Multiple Evidence Layers
                         │
                         ▼
             Export Portable Evidence Bundle
                         │
                         ▼
                 Later Verification
                         │
                         ▼
              Multi-Layer Evidence Recovery
                         │
                         ▼
           Multi-Layer Integrity Verification
                         │
                         ▼
              Comprehensive Forensic Report
```

This layered approach ensures that evidence remains recoverable, verifiable, and resistant to accidental loss or deliberate tampering.

---

# 🎥 Secure Video Recording Workflow

When recording begins, Project Crygan continuously captures video frames while simultaneously generating forensic metadata required for future verification.

Unlike conventional video recorders, the application performs cryptographic operations during and immediately after recording.

## Recording Pipeline

```text
Location Acquisition
        │
        ▼
Start Camera
        │
        ▼
Capture Frames
        │
        ▼
Generate SHA-256 Frame Hashes
        │
        ▼
Build Merkle Tree
        │
        ▼
Generate Perceptual Hashes
        │
        ▼
Acquire RFC3161 Timestamp
        │
        ▼
Create Evidence Package
        │
        ▼
Digitally Sign
        │
        ▼
Encrypt
        │
        ▼
Store Across Multiple Layers
```

---

# 📦 Evidence Package

Project Crygan creates a single encrypted forensic evidence package for every recording.

This package becomes the authoritative source used during future verification.

The package contains forensic metadata rather than the video itself.

## Evidence Package Contents

| Component | Purpose |
|------------|---------|
| UUID | Unique recording identifier |
| Recording Timestamp | Recording time |
| Recording Location | GPS/IP based location |
| Camera Information | Device metadata |
| Frame Count | Total recorded frames |
| SHA-256 Hash Chain | Frame integrity |
| Final Hash | Recording fingerprint |
| Merkle Root | Frame commitment |
| Perceptual Hashes | Visual similarity analysis |
| RFC3161 Timestamp Token | Trusted temporal proof |
| Digital Signature | Evidence authenticity |

After creation, the package is digitally signed and encrypted before storage.

---

# 🔐 Cryptographic Workflow

Project Crygan combines multiple cryptographic mechanisms to protect evidence.

```text
Evidence Metadata
        │
        ▼
Generate SHA-256 Hash Chain
        │
        ▼
Generate Merkle Root
        │
        ▼
Generate Perceptual Hashes
        │
        ▼
Attach Timestamp
        │
        ▼
ECDSA Signature
        │
        ▼
AES-256-GCM Encryption
        │
        ▼
Encrypted Evidence Package
```

Each stage protects a different aspect of the recording.

---

# 🗂 Multi-Layer Evidence Storage

One of Project Crygan's distinguishing characteristics is that evidence is never stored in a single location.

Instead, identical evidence is preserved using multiple independent storage mechanisms.

## Storage Architecture

```text
Encrypted Evidence Package
        │
        ├────────────► Embedded MP4 Evidence
        │
        ├────────────► Companion .crygan Package
        │
        ├────────────► LSB Reference PNG
        │
        ├────────────► Reed–Solomon PNG Chunks
        │
        └────────────► Local Evidence Registry
```

---

## Evidence Storage Layers

| Storage Layer | Purpose |
|---------------|---------|
| Embedded MP4 Evidence | Primary evidence stored inside recorded video |
| Companion `.crygan` Package | Portable encrypted backup |
| LSB Reference PNG | Independent corroborative integrity reference |
| Reed–Solomon PNG Chunks | Recovery when primary package is unavailable |
| SQLite Registry | Local evidence indexing and discovery |

This redundancy allows verification to continue even if one evidence source becomes unavailable.

---

# 🖼 LSB Reference PNG

Project Crygan generates a PNG containing cryptographic reference information embedded using Least Significant Bit (LSB) steganography.

The PNG contains:

- Final SHA-256 hash
- Digital signature
- UUID
- Integrity reference

The LSB PNG serves as an **independent corroborative evidence source**.

It is **not** the primary evidence package.

If modified or recompressed, the LSB verification will fail while the primary cryptographic verification can still succeed if the embedded or companion evidence package remains intact.

---

# 🧩 Reed–Solomon Recovery

To improve evidence resilience, Project Crygan splits the encrypted evidence package into multiple Reed–Solomon encoded chunks.

```text
Encrypted Package
        │
        ▼
Split into Data Blocks
        │
        ▼
Generate Parity Blocks
        │
        ▼
Embed Each Block Into PNG
```

During verification:

```text
Collect PNG Chunks
        │
        ▼
Enough Chunks Available?
        │
     Yes │ No
        ▼
Reconstruct Evidence Package
```

This allows recovery of the encrypted evidence package even when several chunk images are unavailable.

---

# 🗃 Local Evidence Registry

Project Crygan maintains a lightweight SQLite registry containing forensic references for locally recorded evidence.

The registry supports:

- UUID lookup
- Evidence discovery
- Recovery assistance
- Verification history
- Perceptual fingerprint indexing

The registry is used only after higher-priority evidence sources are unavailable.

---

# 🔍 Evidence Recovery Workflow

When verifying a recording, Project Crygan attempts evidence recovery using a prioritized fallback strategy.

## Recovery Priority

```text
Embedded MP4 Evidence
        │
   Not Found
        ▼
Companion .crygan Package
        │
   Not Found
        ▼
Reed–Solomon PNG Recovery
        │
   Not Found
        ▼
SQLite Registry
        │
   Not Found
        ▼
Verification Cannot Proceed
```

Once evidence has been recovered from any source, all subsequent verification uses that recovered evidence package.

---

# 🛡 Multi-Layer Integrity Verification

Project Crygan performs several independent integrity checks.

## Primary Verification

```text
Recover Evidence
        │
        ▼
Decrypt Evidence
        │
        ▼
Verify Signature
        │
        ▼
Compare Frame Count
        │
        ▼
Verify SHA-256 Frame Hash Chain
        │
        ▼
Verify Merkle Commitment
        │
        ▼
Primary Integrity Decision
```

---

## Supporting Verification

Additional forensic evidence is generated through supporting verification mechanisms.

These include:

- RFC3161 Timestamp Verification
- LSB Reference Validation
- Perceptual Hash Analysis
- Frame Localization

These mechanisms provide additional forensic confidence without replacing cryptographic verification.

---

# 🌳 Merkle Tree Verification

The Merkle Tree enables efficient localization of altered frame regions.

Instead of comparing every frame individually, Project Crygan compares the Merkle Root stored in the evidence package against the Merkle Root computed during verification.

If differences exist, the tree traversal identifies affected frame ranges.

---

# 🧠 Perceptual Hash Analysis

Perceptual hashing provides an estimate of visual similarity.

Unlike SHA-256, perceptual hashes remain relatively stable under ordinary compression while changing significantly when visual content changes.

Project Crygan uses perceptual hashing to help distinguish between:

| Scenario | Expected Result |
|----------|----------------|
| Ordinary recompression | High similarity |
| Exposure adjustment | Moderate similarity |
| Saturation adjustment | Moderate similarity |
| Cropping | Low similarity |
| Object removal | Low similarity |
| Frame replacement | Very low similarity |

Perceptual hashing is used as corroborative evidence and should not be interpreted as cryptographic proof.

---

# 📤 Evidence Export

Project Crygan allows investigators to export all required forensic artifacts as a portable evidence bundle.

Typical exported contents include:

```text
Recording.mp4
Recording.crygan
Reference.png
...
manifest.json
```

The exported bundle enables verification on another system without requiring the original recording environment.

---

# 📑 Verification Report

After verification, Project Crygan generates a comprehensive forensic report.

Typical report contents include:

- Evidence source
- Recording timestamp
- Recording location
- Evidence recovery path
- Metadata decryption status
- Digital signature status
- Frame count comparison
- SHA-256 frame hash verification
- Merkle verification
- LSB verification
- Timestamp verification
- Tamper localization
- Perceptual analysis
- Overall integrity verdict

The report is designed to provide investigators with both cryptographic evidence and human-readable forensic observations.

---

# 🧪 Experimental Evaluation

Project Crygan was evaluated using representative tampering scenarios to assess its ability to preserve evidence integrity, recover forensic metadata, and identify modifications made after recording.

The experiments focused on validating the complete forensic pipeline rather than individual cryptographic primitives.

---

# 📋 Test Summary

| Test Scenario | Embedded Evidence | Companion `.crygan` | LSB PNG | Result |
|---------------|------------------|---------------------|---------|--------|
| Original Recording | ✅ | Not Required | ✅ | Integrity Passed |
| Trimmed Video | ❌ Removed by Editing | ✅ Recovered | ✅ | Integrity Failed |
| Exposure / Saturation Editing | ❌ Removed by Editing | ✅ Recovered | ✅ | Integrity Failed |
| LSB PNG Modified | ✅ | Available | ❌ Failed | Integrity Passed |

---

# 📊 Evaluation Results

## ✅ Test 1 — Original Recording

### Objective

Verify an unmodified recording.

### Outcome

- Evidence successfully recovered
- Metadata decrypted
- Signature verified
- Frame hash chain matched
- Merkle commitment matched
- LSB reference validated
- Overall integrity passed

---

## ✂ Test 2 — Trimmed Video

### Objective

Determine whether frame removal can be detected.

### Observations

- Embedded evidence removed during re-encoding
- Companion `.crygan` recovered successfully
- Frame count mismatch detected
- Hash chain mismatch detected
- Merkle mismatch detected
- LSB validation succeeded

### Result

❌ Overall Integrity Failed

---

## 🎨 Test 3 — Exposure & Saturation Editing

### Objective

Evaluate detection of visual modifications.

### Observations

- Frame count unchanged
- Companion package recovered
- Hash chain mismatch
- Merkle mismatch
- Perceptual analysis identified probable visual modifications

### Result

❌ Overall Integrity Failed

---

## 🖼 Test 4 — LSB PNG Tampering

### Objective

Determine whether corruption of the optional PNG affects primary verification.

### Observations

- Embedded evidence recovered
- Signature verified
- Hash chain verified
- Merkle verification succeeded
- LSB validation failed

### Result

✅ Overall Integrity Passed

This demonstrates that the LSB reference acts as an independent corroborative layer and does not invalidate authentic evidence when modified.

---

# 📈 Feature Comparison

| Capability | Conventional Video | Project Crygan |
|------------|-------------------|----------------|
| Video Recording | ✅ | ✅ |
| Cryptographic Integrity | ❌ | ✅ |
| Digital Signatures | ❌ | ✅ |
| Trusted Timestamp | ❌ | ✅ |
| Frame-Level Verification | ❌ | ✅ |
| Tamper Localization | ❌ | ✅ |
| Evidence Recovery | ❌ | ✅ |
| Portable Evidence Package | ❌ | ✅ |
| Multi-Layer Storage | ❌ | ✅ |
| Forensic Reports | ❌ | ✅ |

---

# 📊 Core Functionalities

Project Crygan provides six primary functional modules.

| Module | Description |
|----------|-------------|
| 🎥 Secure Recording | Captures video while generating forensic evidence |
| 📦 Evidence Packaging | Creates encrypted evidence packages |
| 🗃 Multi-Layer Storage | Stores evidence redundantly |
| 🔍 Evidence Recovery | Retrieves evidence using prioritized fallback |
| 🛡 Integrity Verification | Performs cryptographic verification |
| 📑 Report Generation | Produces human-readable forensic reports |

---

# 🚀 Performance Characteristics

The framework is designed for forensic reliability rather than maximum throughput.

Current characteristics include:

- SHA-256 frame hashing
- Merkle Tree generation
- AES-256-GCM encryption
- ECDSA signing
- RFC3161 timestamp validation
- SQLite indexing
- Reed–Solomon encoding

Although these introduce computational overhead, they significantly strengthen evidence authenticity.

---

# ⚠ Current Limitations

Project Crygan is an academic and research-oriented framework.

Current limitations include:

- Embedded evidence may be removed by video editors.
- Companion evidence should be preserved.
- LSB reference is corroborative only.
- Perceptual hashing is not cryptographic proof.
- RFC3161 timestamping depends on network availability.
- Reed–Solomon recovery has limited experimental validation.
- Current implementation targets desktop environments.

---

# 🛠 Development Roadmap

| Status | Feature |
|---------|---------|
| ✅ | Secure Recording |
| ✅ | Cryptographic Evidence Generation |
| ✅ | AES-256-GCM Encryption |
| ✅ | ECDSA Signatures |
| ✅ | Merkle Tree Verification |
| ✅ | SHA-256 Hash Chain |
| ✅ | LSB Reference PNG |
| ✅ | Companion `.crygan` Package |
| ✅ | Evidence Export |
| ✅ | PDF Reports |
| 🚧 | Reed–Solomon Recovery Validation |
| 🚧 | Android Support |
| 🚧 | Deepfake Detection |
| 🚧 | Cloud Synchronization |

---

# 🤝 Contributing

Contributions are welcome.

You can contribute by:

- Reporting issues
- Improving documentation
- Fixing bugs
- Optimizing performance
- Extending verification algorithms
- Improving GUI
- Adding platform support
- Implementing future roadmap features

---

## Development Workflow

```bash
Fork Repository

↓

Create Feature Branch

↓

Commit Changes

↓

Push Branch

↓

Open Pull Request
```

Please ensure that new contributions include appropriate documentation and testing where applicable.

---

# 🐞 Reporting Issues

If you discover a bug or unexpected behaviour:

1. Search existing issues.
2. Create a new issue if necessary.
3. Include:
   - Operating system
   - Python version
   - Steps to reproduce
   - Screenshots or logs
   - Expected behaviour

---

# 📄 License

This project is released under the **MIT License**.

You are free to:

- Use
- Modify
- Distribute
- Fork

while retaining the original license.

See the [`LICENSE`](LICENSE) file for the full license text.

---

# 🙏 Acknowledgements

Project Crygan was developed as a research and software engineering project focusing on digital forensics, cryptography, and secure multimedia evidence preservation.

The project builds upon established concepts in:

- SHA-256 Cryptographic Hashing
- Merkle Trees
- AES-GCM Encryption
- ECDSA Digital Signatures
- RFC 3161 Trusted Timestamping
- Reed–Solomon Error Correction
- OpenCV
- PySide6
- SQLite

Thanks to the open-source community whose libraries and tools made this project possible.

---

# ⭐ Support the Project

If you find Project Crygan useful:

⭐ Star the repository

🍴 Fork the project

🐛 Report issues

💡 Suggest improvements

📢 Share the project

---

<div align="center">

# 🛡 Project Crygan

### Preserving Digital Evidence Through Multi-Layer Cryptographic Integrity Verification

---
**Developed by S. Vinay Narasimha & R. Hemanth Kumar**


</div>
