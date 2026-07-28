"""
config.py
---------
Central configuration for Project Crygan.

All shared constants, filesystem paths, and tunable parameters live here so
that other modules never hard-code magic values. Keeping configuration in a
single place makes the application easier to extend in future versions.
"""

import os


def _resolve_persistent_base_dir() -> str:
    """
    Resolve a stable, writable directory for all of Project Crygan's
    persistent data: encryption keys, the SQLite database, recorded
    videos, and generated reports.

    Per project preference, this lives right next to the application
    itself (the project folder) rather than in an OS-level per-user
    app-data directory -- so `videos/`, `keys/`, and `reports/` are all
    visible, ordinary sub-folders of the project you can browse to
    directly, instead of being tucked away in %APPDATA% / ~/Library /
    ~/.local/share.

    Note for packaged/frozen builds (e.g. a PyInstaller "onefile" .exe):
    in that scenario `__file__` resolves to a temporary extraction
    folder that differs on every launch, which would make keys/videos
    disappear between runs. That's not a concern for running from
    source as-is; if/when this project is packaged for distribution,
    this function is the one place that needs to switch back to an
    OS-level app-data directory.
    """
    return os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------------------
# Base directories
# ---------------------------------------------------------------------------
BASE_DIR = _resolve_persistent_base_dir()

VIDEOS_DIR = os.path.join(BASE_DIR, "videos")
KEYS_DIR = os.path.join(BASE_DIR, "keys")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
DATABASE_PATH = os.path.join(BASE_DIR, "crygan.db")

# Companion lossless PNG frames carrying the small LSB-embedded hash+
# signature reference (see evidence_storage.py's "genuine pixel-domain (LSB)
# steganography" section and recorder.py's stop_recording()). Kept in
# their own folder, separate from the .mp4 evidence videos themselves.
STEGO_REFERENCE_DIR = os.path.join(BASE_DIR, "stego_refs")

# Destination for the Verify screen's "Export Evidence" button: bundles
# everything discovered for one recording (video, companion .crygan file,
# LSB reference PNG, RS chunk PNGs, and a manifest.json) into a single
# folder named after that recording's evidence_id, so it's easy to hand
# to someone else as one self-contained unit instead of several loose
# files scattered across VIDEOS_DIR/KEYS_DIR/STEGO_REFERENCE_DIR.
EVIDENCE_EXPORTS_DIR = os.path.join(BASE_DIR, "evidence_exports")

# ---------------------------------------------------------------------------
# Reed-Solomon erasure-coded chunk reference frames
# ---------------------------------------------------------------------------
# In addition to the single-frame LSB hash+signature reference above, the
# FULL encrypted evidence package is also split into STEGO_CHUNK_DATA_COUNT
# equal chunks, plus STEGO_CHUNK_PARITY_COUNT Reed-Solomon parity chunks,
# each LSB-embedded into its own lossless PNG (see evidence_storage.py's
# "erasure-coded chunk" section). ANY STEGO_CHUNK_DATA_COUNT of the
# resulting (data + parity) chunk frames are enough to fully reconstruct
# the evidence package -- so losing/deleting up to STEGO_CHUNK_PARITY_COUNT
# of these reference frames (or the primary tail-appended payload being
# truncated/corrupted entirely) still allows full recovery of who/when/
# where this recording claims to be from, for later comparison against the
# recomputed frame hash chain.
#
# Reed-Solomon over GF(256) supports at most 255 total symbols per
# codeword, so STEGO_CHUNK_DATA_COUNT + STEGO_CHUNK_PARITY_COUNT must stay
# well under 255 -- 10 total is already generous for typical recordings.
STEGO_CHUNK_DATA_COUNT = 6
STEGO_CHUNK_PARITY_COUNT = 4

os.makedirs(BASE_DIR, exist_ok=True)

for _directory in (VIDEOS_DIR, KEYS_DIR, REPORTS_DIR, STEGO_REFERENCE_DIR, EVIDENCE_EXPORTS_DIR):
    os.makedirs(_directory, exist_ok=True)

# ---------------------------------------------------------------------------
# Key files
# ---------------------------------------------------------------------------
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "private_key.enc")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "public_key.pem")
KEY_SALT_PATH = os.path.join(KEYS_DIR, "key_salt.bin")

# Optional "remember my password" convenience feature (see remember.py) so
# the user doesn't have to retype their session password every launch.
# Stored as its own local encryption key + encrypted blob, separate from
# the actual private key material above.
REMEMBER_LOCAL_KEY_PATH = os.path.join(KEYS_DIR, "remember.key")
REMEMBER_PASSWORD_PATH = os.path.join(KEYS_DIR, "remember.enc")

# ---------------------------------------------------------------------------
# Video recording
# ---------------------------------------------------------------------------
DEFAULT_CAMERA_INDEX = 0
DEFAULT_FRAME_WIDTH = 1280
DEFAULT_FRAME_HEIGHT = 720
DEFAULT_FPS = 30
VIDEO_FOURCC = "mp4v"          # container-compatible codec for OpenCV VideoWriter
VIDEO_EXTENSION = ".mp4"

# ---------------------------------------------------------------------------
# Evidence embedding (tail-appended payload)
# ---------------------------------------------------------------------------
# Marker bytes used to locate the embedded evidence package inside a video
# file. Chosen to be extremely unlikely to occur naturally inside an MP4
# container. See evidence_storage.py for details and known limitations.
EVIDENCE_START_MARKER = b"\x00CRYGAN_EVIDENCE_START\x00"
EVIDENCE_END_MARKER = b"\x00CRYGAN_EVIDENCE_END\x00"

# ---------------------------------------------------------------------------
# Cryptography
# ---------------------------------------------------------------------------
ECC_CURVE_NAME = "SECP384R1"
AES_KEY_SIZE = 32              # AES-256
AES_NONCE_SIZE = 12            # Recommended nonce size for AES-GCM
PBKDF2_ITERATIONS = 390_000
KEY_DERIVATION_SALT_SIZE = 16

# ---------------------------------------------------------------------------
# Frame-level tamper localization & perceptual hashing
# ---------------------------------------------------------------------------
# In addition to the original single rolling SHA-256 chain value
# (frame_hash_chain["final_hash"]), recordings now also commit to a Merkle
# tree built over each frame's own (unchained) SHA-256 hash. This adds two
# capabilities the linear chain can't provide on its own:
#   1. Tamper localization: if verification fails, the app can report
#      *which* frame indices actually differ instead of just "chain
#      broken somewhere" (see crypto_core.py's compute_full_chain_from_video
#      and VerificationEngine.verify()'s Step 4c).
#   2. Single-frame proofs: given just one frame, its index, and a short
#      Merkle proof, anyone can confirm that exact frame was part of the
#      originally recorded sequence -- without needing the entire video
#      file. (crypto_core.py: merkle_proof / verify_merkle_proof.)
#
# Alongside the exact per-frame hash, a perceptual hash (dHash, 64-bit) is
# also computed per frame using only cv2/numpy -- both already hard
# requirements of this app, so this needs no extra dependency. Exact
# SHA-256 hashes change completely from even a single flipped pixel, so
# ordinary lossy re-encoding (e.g. re-uploading to a messaging app) will
# always break an exact-hash check -- that's expected, not a sign of
# tampering. Perceptual hashes change only gradually with visual
# similarity, so when an exact per-frame hash fails to match, comparing
# perceptual hashes lets the app classify each differing frame
# individually as "this looks like ordinary recompression" (small Hamming
# distance) vs. "the visual content actually changed" (large distance).
PERCEPTUAL_HASHING_ENABLED = True
PERCEPTUAL_HASH_SIZE_BYTES = 8  # 64-bit dHash
# Two 64-bit dHash values differing in this many bits or fewer (out of 64)
# are treated as "the same underlying frame, plausibly re-encoded" rather
# than "visually different content." 10/64 (~15%) is a commonly used
# perceptual-hash similarity threshold in the literature; it is
# intentionally conservative (a smaller number would call more genuine
# re-encodes "tampered").
PERCEPTUAL_SIMILARITY_THRESHOLD_BITS = 10

# ---------------------------------------------------------------------------
# Local perceptual-hash evidence registry (out-of-band recovery fallback)
# ---------------------------------------------------------------------------
# No in-file technique -- not the tail-appended payload, not the ISO-BMFF
# uuid box, not any metadata atom -- survives an actual transcode/re-mux of
# the video. That's structural: transcoding rewrites the compressed
# bitstream (and typically the whole container) from scratch, so nothing
# living in the old file's bytes has a hook into the new one.
#
# The only real fix is out-of-band: keep an independent copy of the signed
# evidence somewhere other than the file itself, then re-associate it later
# via content matching. This app keeps that "somewhere else" local (its own
# SQLite database, see project_UI.py's EvidenceDatabase), consistent with
# its existing everything-stays-local design philosophy, rather than a
# public/cloud registry -- see EvidenceDatabase's "local_evidence_registry"
# table.
#
# At recording time, a compact perceptual "fingerprint" (this many evenly
# RELATIVE-position-sampled per-frame dHashes, not fixed absolute frame
# indices, so a transcoded copy with a slightly different frame count still
# lands on approximately the same content at each sample point) is stored
# alongside a redundant copy of the full encrypted evidence payload. If a
# submitted video has no extractable embedded evidence at all, verification
# falls back to fingerprint-matching it against this local registry.
#
# IMPORTANT CAVEAT: a registry match is weaker provenance than file-embedded
# evidence. It depends on trusting this specific installation's local
# database, not just the cryptographic signature chain -- report this
# distinction clearly whenever a registry match is used (see
# VerificationResult.registry_match_used in crypto_core.py).
FINGERPRINT_SAMPLE_COUNT = 32
# Average per-sample Hamming distance (bits, out of 64 per sample) at or
# below which a registry candidate is considered a match. Slightly looser
# than the single-frame PERCEPTUAL_SIMILARITY_THRESHOLD_BITS above since
# this is an average over many samples rather than one exact frame-to-frame
# comparison.
FINGERPRINT_AVERAGE_DISTANCE_THRESHOLD_BITS = 12

# ---------------------------------------------------------------------------
# Trusted timestamping (RFC 3161)
# ---------------------------------------------------------------------------
# An RFC 3161 Time-Stamp Authority (TSA) independently, cryptographically
# attests that the final frame-hash-chain value existed by a given time --
# using the TSA's own server clock, not this machine's local clock (which
# the "timestamp" field on the evidence payload relies on, and which anyone
# can change before recording -- see crypto_core.py's timestamping section
# for the full rationale).
#
# The default below is DigiCert's public timestamping endpoint, widely used
# for code-signing timestamps and free to query without an account. Swap it
# for any other RFC 3161-compliant TSA (e.g. a self-hosted one, or your
# organization's) by changing TSA_URL.
#
# NOTE: this is a best-effort integrity measure, not a full PKI deployment.
# By default, verification trusts whatever signing certificate the TSA
# embeds in its own response -- it does not chain-verify that certificate
# up to a trusted root CA. For stronger guarantees, download that TSA's
# certificate once, over a trusted channel, store it locally, and point
# TSA_CA_CERT_PATH at it; verification will then check the token's
# signature against that pinned certificate instead of trusting whatever
# the token itself carries.
TSA_ENABLED = True
TSA_URL = "http://timestamp.digicert.com"
TSA_HASH_ALGORITHM = "sha256"
TSA_TIMEOUT_SECONDS = 15
TSA_CA_CERT_PATH = None  # optional: path to a pinned CA/TSA certificate (PEM)

# ---------------------------------------------------------------------------
# Location
# ---------------------------------------------------------------------------
# Desktop machines generally lack GPS hardware, so Project Crygan resolves
# an approximate location via IP-based geolocation. This is documented to
# the user; a future version may support attached GPS receivers.
IP_GEOLOCATION_URL = "http://ip-api.com/json/"
LOCATION_TIMEOUT_SECONDS = 6

# ---------------------------------------------------------------------------
# Application metadata
# ---------------------------------------------------------------------------
APP_NAME = "Project Crygan"
APP_VERSION = "0.1.0"
ORGANIZATION_NAME = "Project Crygan (Open Source)"
