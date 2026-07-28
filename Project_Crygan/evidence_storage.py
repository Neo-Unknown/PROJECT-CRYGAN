"""
evidence_storage.py
------------------
Stores, transports, and recovers Project Crygan's encrypted evidence
payload for a recorded video, across several independent mechanisms:

    * Tail-appended, file-level embedding directly inside the video file
      (plus an ISO-BMFF `uuid` box wrapper), without altering playback.
    * A portable companion ".crygan" evidence package that ships
      alongside the video and survives transcoding/re-muxing.
    * A single-frame, pixel-domain (LSB) steganographic reference frame
      carrying just the final hash + signature.
    * Reed-Solomon erasure-coded chunk reference frames, splitting the
      full evidence payload across several LSB-embedded PNGs so that
      partial loss/corruption is still recoverable.

Only the first mechanism above is "steganography embedded in the video
file" in the strict sense the module was originally named for; the
rest are additional, independent storage/recovery paths for the same
underlying encrypted payload. `validate_payload` (further below) checks
the structural/checksum integrity of a recovered record regardless of
which of these mechanisms produced it.

======================================================================
CHOSEN EMBEDDING APPROACH (documented per project requirements)
======================================================================
Directly manipulating a compressed video bitstream (e.g. flipping bits
inside H.264/MP4 frame data, classic LSB-in-pixel steganography before
encoding, etc.) is unreliable for this project's goals:

    * It typically requires re-encoding the footage, which is exactly the
      kind of lossy transformation we do NOT want to apply to evidentiary
      video -- re-encoding would itself alter the frame data we are trying
      to attest to.
    * Compressed-domain bit-twiddling is fragile: it is easily destroyed
      by re-muxing, easily corrupts the bitstream if done incorrectly, and
      is highly codec/container-specific.

Instead, Project Crygan v0.1 uses **file-level appended-payload
steganography**: the encrypted evidence payload is written as a
self-describing structured record appended immediately after the video
stream's natural end-of-file. Virtually all common video containers
(MP4/MOV/AVI/MKV) are read by players according to an internal index
(e.g. the MP4 `moov` atom) that describes exactly where the playable
data lives; players stop reading once that data is consumed and silently
ignore any additional trailer bytes. This means:

    * The video plays back byte-for-byte identically in any standard
      media player -- there is zero risk of visual artifacts because we
      never touch a single pixel or video byte.
    * No re-encoding occurs, so video quality is perfectly preserved
      (lossless with respect to the original capture).
    * Embedding and extraction are simple, fast, and memory-efficient
      even for long recordings, since we only ever read/write a small
      chunk of data near the end of the file rather than the whole video.

This is a pragmatic MVP technique, not true bitstream-level
steganography. The public API below (`embed_payload`, `extract_payload`,
`validate_payload`) is intentionally the *only* place that knows how
data is hidden in the file. A future version can swap this
implementation for genuine frame-level steganography (e.g. embedding
inside odd, lossless-encoded marker frames, or a custom MP4 `free`/`skip`
atom placed before `mdat`) without changing any calling code elsewhere
in the project, since recorder.py and verification.py only ever call
these three functions.

======================================================================
PAYLOAD WIRE FORMAT
======================================================================
The structured record appended to the video file has the following
layout, chosen for forward compatibility (future versions can extend it
without breaking older readers):

    +----------------------+------------------------------------------+
    | Field                | Size                                     |
    +----------------------+------------------------------------------+
    | Magic Header         | MAGIC_HEADER_SIZE bytes (fixed constant) |
    | Payload Version       | 1 byte, unsigned integer                |
    | Payload Length        | 8 bytes, big-endian unsigned integer    |
    | Encrypted Payload     | <Payload Length> bytes                  |
    | Checksum (SHA-256)    | 32 bytes                                |
    +----------------------+------------------------------------------+

The checksum is computed over (Magic Header || Version || Length ||
Encrypted Payload) and provides fast, dependency-free corruption
detection independent of the AES-GCM authentication that already
protects the plaintext evidence metadata one layer up (see
crypto_utils.py). Catching corruption here, before decryption is even
attempted, produces clearer error messages for the user.

Only the *encrypted* payload is ever embedded -- this module has no
knowledge of, and never touches, plaintext evidence data.
"""

import hashlib
import os
import struct
import uuid as _uuid_module

# ---------------------------------------------------------------------------
# Wire format constants
# ---------------------------------------------------------------------------
MAGIC_HEADER = b"CRYGAN-EVID"     # 11-byte fixed marker, improbable in video data
CURRENT_PAYLOAD_VERSION = 1
SUPPORTED_PAYLOAD_VERSIONS = (1,)

VERSION_FIELD_SIZE = 1
LENGTH_FIELD_SIZE = 8            # 8-byte big-endian unsigned length
CHECKSUM_SIZE = 32               # SHA-256 digest size

HEADER_PREFIX_SIZE = len(MAGIC_HEADER) + VERSION_FIELD_SIZE + LENGTH_FIELD_SIZE
MIN_RECORD_SIZE = HEADER_PREFIX_SIZE + CHECKSUM_SIZE  # record with an empty payload

# A fixed, well-known UUID identifying "this custom ISO-BMFF box belongs
# to Project Crygan," generated once via uuid5 so it's a stable,
# reproducible 16-byte value rather than something random per build. Used
# to wrap the evidence record in a standards-compliant `uuid` extension
# box -- see _wrap_in_iso_bmff_uuid_box()'s docstring for why.
CRYGAN_BOX_UUID = _uuid_module.uuid5(_uuid_module.NAMESPACE_DNS, "crygan.evidence.box").bytes

# File extension for the standalone companion evidence file (see this
# module's "Companion .crygan evidence file" section below). Written next
# to the video, same directory, same base name -- e.g. "clip001.mp4" gets
# a "clip001.crygan" sidecar.
COMPANION_FILE_EXTENSION = ".crygan"

# How far from the end of the file we search for the magic header when
# extracting. Evidence payloads are small (a few kilobytes of JSON, even
# after encryption), so a generous multi-megabyte window comfortably
# contains the full record while avoiding ever reading a large video
# file into memory. This keeps extraction fast and RAM-light even for
# long, multi-minute recordings.
TAIL_SEARCH_WINDOW_BYTES = 8 * 1024 * 1024  # 8 MB


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------
class EvidenceStorageError(Exception):
    """Base class for all evidence storage/recovery failures (tail-append
    embedding, companion package, LSB reference frames, and Reed-Solomon
    chunk recovery alike)."""


class PayloadNotFoundError(EvidenceStorageError):
    """Raised when no embedded evidence payload could be located."""


class PartialPayloadError(EvidenceStorageError):
    """Raised when a payload record was found but appears truncated."""


class PayloadCorruptedError(EvidenceStorageError):
    """Raised when a payload record fails structural/checksum validation."""


class UnsupportedPayloadVersionError(EvidenceStorageError):
    """Raised when a payload declares a version this build cannot parse."""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def embed_payload(video_path: str, encrypted_payload: bytes, version: int = CURRENT_PAYLOAD_VERSION):
    """
    Embed an encrypted evidence payload into a video file.

    Only the already-encrypted payload bytes (produced upstream by
    crypto_utils.encrypt_json) are ever written here -- this function
    never sees or embeds plaintext evidence data.

    Args:
        video_path: Path to the already-written, fully playable video file.
        encrypted_payload: Encrypted evidence bytes to embed.
        version: Wire-format version to write (defaults to the current
            version). Exposed mainly for testing/forward compatibility.

    Raises:
        EvidenceStorageError: if the payload cannot be written to disk.
    """
    if version not in SUPPORTED_PAYLOAD_VERSIONS:
        raise UnsupportedPayloadVersionError(
            f"Cannot embed payload: version {version} is not supported by this build."
        )

    record = _build_record(encrypted_payload, version)
    boxed_record = _wrap_in_iso_bmff_uuid_box(record)

    try:
        with open(video_path, "ab") as f:
            f.write(boxed_record)
    except OSError as exc:
        raise EvidenceStorageError(f"Failed to embed evidence payload into video: {exc}") from exc


def extract_payload(video_path: str) -> bytes:
    """
    Locate, validate, and extract the encrypted evidence payload embedded
    in a video file.

    This function only performs *structural* validation of the embedded
    record (magic header, version, length, checksum). It intentionally
    does not decrypt anything or verify signatures -- that logic already
    exists in verification.py and crypto_utils.py, and is not duplicated
    here. The caller is expected to pass the returned encrypted bytes on
    to the existing decryption/signature/hash-chain verification pipeline.

    Args:
        video_path: Path to a video file to inspect.

    Returns:
        The raw encrypted evidence payload bytes.

    Raises:
        PayloadNotFoundError: no embedded payload could be located.
        PartialPayloadError: a payload was found but is truncated.
        PayloadCorruptedError: the payload's checksum does not match.
        UnsupportedPayloadVersionError: the payload's version is unknown.
    """
    tail = _read_tail(video_path)

    magic_pos = tail.rfind(MAGIC_HEADER)
    if magic_pos == -1:
        raise PayloadNotFoundError(
            "No embedded Project Crygan evidence payload was found in this video. "
            "It may not have been recorded with Project Crygan, or the evidence "
            "data has been removed."
        )

    record = tail[magic_pos:]
    return validate_payload(record)


# ---------------------------------------------------------------------------
# Companion .crygan evidence package
# ---------------------------------------------------------------------------
"""
Neither in-file embedding (tail-append or the ISO-BMFF uuid box) nor the
local out-of-band registry actually solve the problem of handing evidence
to someone else: an in-file copy dies the moment the video is transcoded,
and the local registry (see crypto_core.py's sample_fingerprint/
compare_fingerprints and config.py's "Local perceptual-hash evidence
registry" section) never leaves the recording machine at all -- a judge,
forensic lab, or another investigator's computer doesn't have it.

The fix real forensic workflows use is a portable, cryptographically
protected sidecar EVIDENCE PACKAGE that accompanies the video throughout
the chain of custody: "video.mp4" ships alongside "video.crygan" as a
pair. The .crygan file contains everything this app already generates per
recording -- the encrypted evidence blob (which itself carries the ECC
signature, public key, Merkle root, per-frame hashes, timestamp, GPS, and
software version once decrypted) -- just also saved as its own portable
file rather than existing only inside the video.

Whoever receives both files can verify entirely offline, with no
dependency on the original recording device or its local database -- and
if the video itself later gets transcoded/re-encoded (stripping any
in-file evidence), the companion package still carries everything needed
for perceptual-hash-based tamper localization (see
VerificationEngine.verify()'s priority order below).

CHAIN OF CUSTODY: video.mp4 and video.crygan are one inseparable evidence
set, not two independent files. Handle, copy, and submit them together --
losing the .crygan file leaves the video unverifiable the moment it's
transcoded, and losing the video leaves the .crygan file with nothing to
attest to. Documentation/reports describing this system should refer to
the pair collectively as the recording's evidence package, not describe
video.crygan as merely an auxiliary "sidecar file."

Recovery priority, highest first -- and VerificationResult.evidence_source
(see crypto_core.py) always reports plainly which of these was actually
used, so nothing about how a given recording was recovered is left
implicit or hidden from whoever is reading a verification report:
    1. Evidence embedded in the file itself (fastest, most convenient)
    2. This companion .crygan evidence package (survives transcoding AND
       travels with the video to any other machine)
    3. Reed-Solomon PNG chunk reconstruction (partial-loss recovery)
    4. The local out-of-band registry (last resort: same-machine only)
"""


def companion_file_path_for(video_path: str) -> str:
    """Return the sidecar '.crygan' companion file path for a given video
    (same directory, same base name, .crygan extension)."""
    base, _ = os.path.splitext(video_path)
    return base + COMPANION_FILE_EXTENSION


def write_companion_file(video_path: str, encrypted_payload: bytes, version: int = CURRENT_PAYLOAD_VERSION) -> str:
    """
    Write the same wire-format evidence record used for in-file embedding
    to a standalone sidecar file next to the video. Returns the path
    written to.

    Uses the exact same _build_record()/validate_payload() wire format as
    in-file embedding, so all existing structural-validation logic (magic
    header, version, length, checksum) is reused unchanged here -- this
    is genuinely the same record, just also saved as its own file.

    Raises EvidenceStorageError if the file can't be written.
    """
    if version not in SUPPORTED_PAYLOAD_VERSIONS:
        raise UnsupportedPayloadVersionError(
            f"Cannot write companion file: version {version} is not supported by this build."
        )
    record = _build_record(encrypted_payload, version)
    path = companion_file_path_for(video_path)
    try:
        with open(path, "wb") as f:
            f.write(record)
    except OSError as exc:
        raise EvidenceStorageError(f"Failed to write companion .crygan evidence file: {exc}") from exc
    return path


def read_companion_file(companion_path: str) -> bytes:
    """
    Read and structurally validate a standalone `.crygan` companion
    evidence file, returning the encrypted evidence payload it contains.

    Raises EvidenceStorageError (or a subclass) if the file is missing,
    unreadable, or fails structural validation -- same exception types as
    extract_payload(), so callers can handle both the same way.
    """
    try:
        with open(companion_path, "rb") as f:
            data = f.read()
    except OSError as exc:
        raise EvidenceStorageError(f"Failed to read companion .crygan evidence file: {exc}") from exc

    magic_pos = data.find(MAGIC_HEADER)
    if magic_pos == -1:
        raise PayloadNotFoundError(
            "This .crygan file does not contain a recognizable Project Crygan evidence record."
        )
    return validate_payload(data[magic_pos:])


def validate_payload(record: bytes) -> bytes:
    """
    Validate a raw payload record (as located inside a video's byte
    stream, starting at the magic header) and return the encrypted
    payload it contains if valid.

    This is exposed as a standalone function -- separate from
    extract_payload -- so that the structural validation logic can be
    unit-tested directly against hand-built byte sequences, and so that
    a future embedding method can reuse the exact same validation rules
    by handing it the raw record bytes however it located them.

    Args:
        record: Bytes beginning at the magic header. May contain
            trailing bytes beyond the end of the record (they are
            ignored once the declared payload length is consumed).

    Returns:
        The encrypted evidence payload bytes.

    Raises:
        PartialPayloadError: not enough bytes present to form a full record.
        UnsupportedPayloadVersionError: unknown payload version.
        PayloadCorruptedError: checksum mismatch or malformed structure.
    """
    if len(record) < MIN_RECORD_SIZE:
        raise PartialPayloadError(
            "Embedded evidence payload is incomplete (fewer bytes present than "
            "the minimum possible record size). The video file may be truncated."
        )

    offset = 0

    magic = record[offset : offset + len(MAGIC_HEADER)]
    offset += len(MAGIC_HEADER)
    if magic != MAGIC_HEADER:
        # validate_payload is always called with `record` starting at a
        # located magic header, so this should not normally happen -- but
        # guard against callers passing arbitrary bytes directly.
        raise PayloadCorruptedError("Magic header mismatch; not a valid Project Crygan payload record.")

    version = record[offset]
    offset += VERSION_FIELD_SIZE
    if version not in SUPPORTED_PAYLOAD_VERSIONS:
        raise UnsupportedPayloadVersionError(
            f"Embedded payload uses version {version}, which this build of "
            f"Project Crygan does not support (supported: {SUPPORTED_PAYLOAD_VERSIONS})."
        )

    length_bytes = record[offset : offset + LENGTH_FIELD_SIZE]
    offset += LENGTH_FIELD_SIZE
    if len(length_bytes) != LENGTH_FIELD_SIZE:
        raise PartialPayloadError("Embedded evidence payload is missing its length field.")
    (payload_length,) = struct.unpack(">Q", length_bytes)

    payload_end = offset + payload_length
    checksum_end = payload_end + CHECKSUM_SIZE

    if len(record) < checksum_end:
        raise PartialPayloadError(
            "Embedded evidence payload is truncated: fewer bytes are present "
            "than the declared payload length plus checksum. The video file "
            "may have been cut short or partially corrupted."
        )

    encrypted_payload = record[offset:payload_end]
    stored_checksum = record[payload_end:checksum_end]

    expected_checksum = hashlib.sha256(record[:payload_end]).digest()
    if stored_checksum != expected_checksum:
        raise PayloadCorruptedError(
            "Embedded evidence payload failed checksum validation. The video "
            "file has likely been modified or corrupted after recording."
        )

    return encrypted_payload


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
def _build_record(encrypted_payload: bytes, version: int) -> bytes:
    """Construct the full wire-format record for a given encrypted payload."""
    header = MAGIC_HEADER + bytes([version]) + struct.pack(">Q", len(encrypted_payload))
    body = header + encrypted_payload
    checksum = hashlib.sha256(body).digest()
    return body + checksum


def _wrap_in_iso_bmff_uuid_box(record: bytes) -> bytes:
    """
    Wrap `record` (the existing MAGIC_HEADER/version/length/payload/
    checksum record, unchanged) in a standards-compliant, top-level
    ISO/IEC 14496-12 ("ISO Base Media File Format" -- the format MP4 is
    built on) `uuid` extension box.

    WHY: previously, the evidence record was appended as raw bytes after
    the end of the video's real box structure (ftyp/moov/mdat) --
    functionally fine for byte-for-byte file copies, but a strict
    ISO-BMFF-aware tool sees "a valid MP4 followed by an unrecognized
    trailing blob," which some validators/upload pipelines flag or strip
    as corruption. `uuid` is a box type the spec explicitly reserves for
    vendor/custom extensions, and compliant parsers are required to be
    able to skip over an unrecognized box safely -- so wrapping the exact
    same bytes this way makes the file a well-formed, standards-compliant
    container instead of "MP4 + mystery bytes," with zero change to what
    the record actually contains or how it's validated.

    WHAT THIS DOES NOT DO: it does not make the payload survive active
    container rewriting. Tools that re-mux or transcode the file (e.g.
    `ffmpeg -i in.mp4 out.mp4` without explicitly preserving unknown
    boxes, or most social-media re-encoding pipelines) will typically
    still drop this box, exactly as they would have dropped the previous
    raw trailing bytes -- no purely file-level technique can survive
    someone else's encoder rewriting the video from scratch. This change
    is about standards compliance and avoiding "corrupt file" false
    positives on simple copies/uploads, not about transcode resilience
    (see this module's docstring for the existing, honest limitations on
    that front, and config.py's perceptual-hashing section for the
    complementary mitigation that *is* transcode-tolerant).

    No changes to moov's chunk-offset tables (stco/co64) are needed
    because this box is appended strictly AFTER the video's existing
    top-level boxes -- nothing already written on disk shifts position.

    extract_payload() needs no changes to understand files written this
    way: it locates MAGIC_HEADER by searching backwards from EOF, which
    finds it identically whether or not a box header precedes it. Videos
    embedded before this function existed (plain trailing bytes, no box
    header) also still extract correctly, unchanged.
    """
    box_type = b"uuid"
    body = CRYGAN_BOX_UUID + record
    size32 = 8 + len(body)  # 4-byte size field + 4-byte type field + body

    if size32 < 2**32:
        return struct.pack(">I", size32) + box_type + body

    # ISO-BMFF "largesize" extension for the (practically unreachable, for
    # this app's small JSON-based payloads) case of a >4GB box: a size
    # field of exactly 1 signals that a real 8-byte size immediately
    # follows the box type.
    size64 = 16 + len(body)  # 4 (size=1) + 4 (type) + 8 (largesize) + body
    return struct.pack(">I", 1) + box_type + struct.pack(">Q", size64) + body


def _read_tail(video_path: str) -> bytes:
    """
    Read a bounded chunk from the end of the file, so extraction never
    has to load an entire (potentially large, multi-minute) video into
    memory. Since the payload is always appended at the very end of the
    file, this is sufficient to locate it regardless of overall video size.
    """
    try:
        file_size = os.path.getsize(video_path)
    except OSError as exc:
        raise EvidenceStorageError(f"Failed to access video file: {exc}") from exc

    read_size = min(file_size, TAIL_SEARCH_WINDOW_BYTES)
    start_offset = file_size - read_size

    try:
        with open(video_path, "rb") as f:
            f.seek(start_offset)
            return f.read(read_size)
    except OSError as exc:
        raise EvidenceStorageError(f"Failed to read video file: {exc}") from exc


# ---------------------------------------------------------------------------
# Genuine pixel-domain (LSB) steganography for a small tamper-evident
# reference -- ADDED capability, hybrid design
# ---------------------------------------------------------------------------
# Everything above this point is the original, unchanged file-level
# "appended after EOF" embedding used for the *full* encrypted evidence
# package (this remains exactly as-is; it is still what stop_recording()
# uses to store the complete evidence metadata).
#
# This section adds a second, independent, and genuinely pixel-level LSB
# steganography scheme, but only for a *small* tamper-evident reference --
# specifically the frame hash chain's final hash plus its ECDSA signature
# (a few hundred bytes), not the full evidence package. It hides those
# bytes inside the least-significant bit of every color channel byte of a
# single real video frame, exactly like classic image LSB steganography.
#
# WHY THIS IS A SEPARATE (LOSSLESS) PNG RATHER THAN BEING RE-MUXED BACK
# INTO THE .mp4 ITSELF:
#
#   1. Self-reference paradox: the reference to hide *is* a hash of the
#      recording's frames. If we hid it inside one of those same frames
#      and then hashed the frames again for the official chain hash, that
#      hash would depend on data derived from itself -- and modifying the
#      frame after the fact (to embed a hash computed before modification)
#      would make that frame's post-embedding bytes no longer match the
#      official recorded chain hash, so every single legitimate recording
#      would fail its own tamper check. The official chain hash therefore
#      has to be computed on the frames exactly as encoded -- untouched.
#
#   2. Lossy compression destroys LSBs: this project's video codec
#      (mp4v, or whatever the OS/OpenCV build defaults to) is a lossy
#      codec. Re-encoding a frame after flipping single least-significant
#      bits essentially never survives DCT quantization -- the hidden
#      bits would silently vanish, which would be worse than not having
#      this feature at all (it would look like tamper-evidence that
#      quietly does nothing). Rewriting/appending compressed video
#      samples into an already-finalized MP4 container without touching
#      the samples that were already hashed would require a real MP4
#      muxer patching moov/mdat atoms by hand -- fragile and well beyond
#      what a reliable, portable implementation can guarantee here.
#
# The approach below sidesteps both problems: after the video is fully
# recorded, hashed, and signed (all unchanged), the *first frame* of the
# now-finished, already-hashed video is decoded once more, the small
# hash+signature reference is LSB-embedded into a COPY of that frame's
# pixels, and that modified copy is saved as its own lossless PNG file
# alongside the video (see recorder.py). The original .mp4 and its
# already-computed chain hash are never touched. The PNG is a genuine
# pixel-level steganographic artifact -- visually identical to the
# original frame, with the reference hidden throughout its pixel data --
# that a verifier can optionally supply in addition to the video to get
# an extra, independent cross-check of the hash + signature, immune to
# the lossy video codec because PNG itself is lossless.
# ---------------------------------------------------------------------------

# Both the LSB single-frame reference and the RS chunk frames below embed
# this same fixed-size, content-level "which recording is this?" ID
# (the recording's UUID evidence_id, as 16 raw bytes) directly in their
# pixel-hidden header. This is what lets recovery discover and group
# these PNGs by their actual content instead of relying on the video's
# current filename, which breaks the moment a video is cropped, trimmed,
# renamed, or moved by a third-party tool -- see discover_evidence_pngs()
# below.
EVIDENCE_ID_SIZE = 16  # a uuid.UUID's raw byte length

LSB_MAGIC = b"CRYGAN-LSB1"      # distinct from the tail-append MAGIC_HEADER
LSB_LENGTH_FIELD_SIZE = 4        # 4-byte big-endian length (reference data is tiny)
LSB_CHECKSUM_SIZE = 32           # SHA-256


class LsbPayloadNotFoundError(EvidenceStorageError):
    """Raised when no valid LSB-embedded reference could be located in a frame."""


class LsbPayloadCorruptedError(EvidenceStorageError):
    """Raised when an LSB-embedded reference fails checksum validation."""


class LsbCapacityError(EvidenceStorageError):
    """Raised when a frame is too small to hold the reference via 1-bit-per-channel LSB embedding."""


def pack_reference(final_hash: bytes, signature: bytes) -> bytes:
    """
    Pack the small tamper-evident reference (chain final hash + ECDSA
    signature) into a single length-prefixed byte string suitable for
    LSB embedding.
    """
    if len(final_hash) > 0xFF:
        raise EvidenceStorageError("final_hash is unexpectedly large for LSB packing.")
    return bytes([len(final_hash)]) + final_hash + signature


def unpack_reference(data: bytes):
    """Reverse of pack_reference(). Returns (final_hash: bytes, signature: bytes)."""
    if not data:
        raise LsbPayloadCorruptedError("Empty LSB reference payload.")
    hash_len = data[0]
    final_hash = data[1 : 1 + hash_len]
    signature = data[1 + hash_len :]
    if len(final_hash) != hash_len:
        raise LsbPayloadCorruptedError("LSB reference payload is truncated (hash length mismatch).")
    return final_hash, signature


def _build_lsb_record(evidence_id: bytes, reference_bytes: bytes) -> bytes:
    if len(evidence_id) != EVIDENCE_ID_SIZE:
        raise EvidenceStorageError(
            f"evidence_id must be exactly {EVIDENCE_ID_SIZE} bytes, got {len(evidence_id)}."
        )
    header = LSB_MAGIC + evidence_id + struct.pack(">I", len(reference_bytes))
    body = header + reference_bytes
    checksum = hashlib.sha256(body).digest()
    return body + checksum


def lsb_capacity_bytes(frame) -> int:
    """Number of bytes that can be hidden in `frame` at 1 bit per color channel byte."""
    return frame.size // 8  # frame.size == height * width * channels (uint8 elements)


def embed_lsb_reference(frame, evidence_id: bytes, reference_bytes: bytes):
    """
    Return a COPY of `frame` (a numpy uint8 array, e.g. as read by
    cv2.VideoCapture/cv2.imread) with `reference_bytes` hidden in the
    least-significant bit of every color channel byte, in raster order,
    starting from the first byte.

    `evidence_id` is the recording's own unique evidence ID (16 raw
    bytes, e.g. `uuid.UUID(evidence_id_str).bytes`), embedded in the
    record's plaintext header. This lets a verifier later recognize
    "which recording does this PNG belong to?" purely from the PNG's own
    pixel content -- without depending on its filename, which does not
    survive being renamed, moved, or re-saved by an external tool.

    Uses classic 1-bit-per-channel-byte LSB steganography: each bit of
    the record (magic + evidence_id + length + reference_bytes +
    checksum) replaces the lowest-order bit of one channel byte,
    changing that byte's value by at most 1 out of 255 -- imperceptible
    to the eye, exactly as described for classic image LSB embedding.

    Raises:
        LsbCapacityError: if the frame is too small to hold the record.
    """
    record = _build_lsb_record(evidence_id, reference_bytes)
    record_bits = "".join(f"{byte:08b}" for byte in record)
    num_bits = len(record_bits)

    capacity_bits = frame.size
    if num_bits > capacity_bits:
        raise LsbCapacityError(
            f"Frame is too small to hold the LSB reference: needs {num_bits} bits, "
            f"frame only has {capacity_bits} channel-byte slots available."
        )

    flat = frame.flatten().copy()
    for i, bit_char in enumerate(record_bits):
        bit = 1 if bit_char == "1" else 0
        flat[i] = (flat[i] & 0xFE) | bit  # clear LSB, then set it to our bit

    return flat.reshape(frame.shape)


def extract_lsb_reference(frame):
    """
    Reverse of embed_lsb_reference(): read the least-significant bit of
    every color channel byte of `frame` (in the same raster order used
    at embed time), reconstruct the record, validate its magic header
    and checksum, and return (evidence_id, reference_bytes).

    Raises:
        LsbPayloadNotFoundError: the magic header doesn't match (this
            frame doesn't contain a valid LSB reference, or was read in
            a different byte order than it was embedded in).
        LsbPayloadCorruptedError: the record's checksum doesn't match
            (the frame has been altered/recompressed since embedding).
    """
    flat = frame.flatten()

    fixed_header_len = len(LSB_MAGIC) + EVIDENCE_ID_SIZE + LSB_LENGTH_FIELD_SIZE
    header_bits_needed = fixed_header_len * 8
    if flat.size < header_bits_needed:
        raise LsbPayloadNotFoundError("Frame is too small to contain an LSB reference header.")

    header_bits = "".join(str(flat[i] & 1) for i in range(header_bits_needed))
    header_bytes = bytes(
        int(header_bits[i : i + 8], 2) for i in range(0, len(header_bits), 8)
    )

    magic = header_bytes[: len(LSB_MAGIC)]
    if magic != LSB_MAGIC:
        raise LsbPayloadNotFoundError(
            "No valid Project Crygan LSB reference found in this frame "
            "(magic header mismatch)."
        )

    evidence_id = header_bytes[len(LSB_MAGIC) : len(LSB_MAGIC) + EVIDENCE_ID_SIZE]
    (payload_length,) = struct.unpack(">I", header_bytes[len(LSB_MAGIC) + EVIDENCE_ID_SIZE :])

    total_record_bytes = fixed_header_len + payload_length + LSB_CHECKSUM_SIZE
    total_bits_needed = total_record_bytes * 8
    if flat.size < total_bits_needed:
        raise LsbPayloadCorruptedError(
            "LSB reference is truncated: the declared payload length needs more bits "
            "than this frame contains. The frame may have been resized or corrupted."
        )

    all_bits = "".join(str(flat[i] & 1) for i in range(total_bits_needed))
    record = bytes(int(all_bits[i : i + 8], 2) for i in range(0, len(all_bits), 8))

    body = record[: fixed_header_len + payload_length]
    stored_checksum = record[fixed_header_len + payload_length :]
    expected_checksum = hashlib.sha256(body).digest()
    if stored_checksum != expected_checksum:
        raise LsbPayloadCorruptedError(
            "LSB reference failed checksum validation. The reference frame has "
            "likely been modified, recompressed, or corrupted since it was created."
        )

    reference_bytes = body[fixed_header_len:]
    return evidence_id, reference_bytes


# ---------------------------------------------------------------------------
# Reed-Solomon erasure-coded chunk reference frames -- ADDED capability
# ---------------------------------------------------------------------------
# Everything above this point (the tail-append full-payload embedding, and
# the single-frame LSB hash+signature reference) is unchanged. This
# section adds a THIRD, independent, optional recovery mechanism for the
# *same* encrypted evidence blob that embed_payload() already appends to
# the end of the video file.
#
# WHY: the tail-append approach is simple and works great as long as the
# file's trailing bytes survive intact. But it is a single point of
# failure -- if the video file is later truncated, re-muxed, partially
# corrupted, or someone deliberately strips the trailer, the ENTIRE
# evidence package (GPS, timestamp, signature, recorded hash) becomes
# unrecoverable in one shot, even though most of the video's actual frame
# data is still sitting right there on disk.
#
# THE FIX (matches the erasure-coding architecture): split the encrypted
# evidence blob into STEGO_CHUNK_DATA_COUNT equal-size chunks, then use a
# systematic Reed-Solomon erasure code over GF(256) to generate
# STEGO_CHUNK_PARITY_COUNT additional parity chunks, such that ANY
# STEGO_CHUNK_DATA_COUNT of the (data + parity) chunks -- no matter which
# ones -- are enough to reconstruct the original blob exactly. Each chunk
# is then LSB-embedded (via the same 1-bit-per-channel-byte technique
# used above for the single hash+signature reference) into its own
# lossless PNG, decoded from a frame spread evenly through the finished
# recording. These PNGs are saved as tamper-evident "reference chunks"
# next to the video (see recorder.py's stop_recording()).
#
# This is purely additive and never blocking: if reedsolo isn't
# installed, or chunk generation fails for any reason, the recording
# still completes normally with its primary tail-appended payload intact
# -- exactly the same fail-open philosophy as the single-frame reference
# above.
#
# HOW THE ERASURE CODE WORKS (systematic RS via column transposition):
# View the STEGO_CHUNK_DATA_COUNT data chunks as rows of a matrix, all
# the same length. For each COLUMN (one byte position, same offset in
# every chunk), take the STEGO_CHUNK_DATA_COUNT bytes at that position as
# a short message and Reed-Solomon-encode it with STEGO_CHUNK_PARITY_COUNT
# parity symbols appended -- a completely ordinary, small RS codeword.
# Stacking the parity symbol produced at each column back into
# STEGO_CHUNK_PARITY_COUNT new rows gives whole parity CHUNKS the same
# length as the data chunks. Reconstructing later is the same idea in
# reverse: for each column, take whichever of the (data + parity) bytes
# at that position are still available, mark the missing ones as
# "erasures" (known-missing, not just wrong -- which lets RS correct up
# to STEGO_CHUNK_PARITY_COUNT of them, not just half that many), and
# RS-decode to recover the original data bytes for that column.
#
# Requires the optional `reedsolo` package (pure Python, no compiler
# needed):
#     pip install reedsolo
# ---------------------------------------------------------------------------

CHUNK_MAGIC = b"CRYGAN-CHNK1"     # distinct from both MAGIC_HEADER and LSB_MAGIC
# evidence_id (16 raw bytes, see EVIDENCE_ID_SIZE above) then chunk_index,
# total_chunks, num_data_chunks, payload_length. Carrying the recording's
# own evidence_id in every chunk is what lets discover_evidence_pngs()
# below group a folder full of chunk PNGs by which recording they
# actually belong to, from their own pixel content -- instead of trusting
# a filename convention that a crop/trim/rename breaks.
CHUNK_HEADER_STRUCT = f">{EVIDENCE_ID_SIZE}sHHHI"
CHUNK_CHECKSUM_SIZE = 32          # SHA-256


class ChunkNotFoundError(EvidenceStorageError):
    """Raised when no valid erasure-coded chunk reference could be located in a frame."""


class ChunkCorruptedError(EvidenceStorageError):
    """Raised when a chunk reference frame fails checksum validation."""


class InsufficientChunksError(EvidenceStorageError):
    """Raised when fewer valid chunks are available than are needed to reconstruct the data."""


def _require_reedsolo():
    try:
        from reedsolo import RSCodec, ReedSolomonError
    except ImportError as exc:
        raise EvidenceStorageError(
            "The optional 'reedsolo' package is not installed, so erasure-coded "
            "chunk reference frames can't be created or read. Install it with: "
            "pip install reedsolo"
        ) from exc
    return RSCodec, ReedSolomonError


def erasure_encode(data: bytes, num_data_chunks: int, num_parity_chunks: int) -> list:
    """
    Split `data` into `num_data_chunks` equal-size chunks and produce
    `num_parity_chunks` additional Reed-Solomon parity chunks, such that
    ANY `num_data_chunks` of the returned (num_data_chunks +
    num_parity_chunks) chunks are sufficient to reconstruct `data`
    exactly, regardless of which ones are missing.

    Returns:
        A list of (num_data_chunks + num_parity_chunks) byte-strings, all
        the same length. Index 0..num_data_chunks-1 are the original data
        (in order); the rest are parity.

    Raises:
        EvidenceStorageError: if reedsolo isn't installed, or the total
            chunk count exceeds GF(256)'s 255-symbol-per-codeword limit.
    """
    RSCodec, _ = _require_reedsolo()

    total_chunks = num_data_chunks + num_parity_chunks
    if total_chunks > 255:
        raise EvidenceStorageError(
            f"Reed-Solomon over GF(256) supports at most 255 total chunks; "
            f"{num_data_chunks} data + {num_parity_chunks} parity = {total_chunks} requested."
        )

    # Prefix with the original (unpadded) length so we can trim the
    # trailing zero-padding back off after reconstruction.
    prefixed = struct.pack(">I", len(data)) + data

    chunk_len = -(-len(prefixed) // num_data_chunks)  # ceil division
    padded = prefixed.ljust(chunk_len * num_data_chunks, b"\x00")

    data_chunks = [padded[i * chunk_len : (i + 1) * chunk_len] for i in range(num_data_chunks)]

    rsc = RSCodec(num_parity_chunks)
    parity_chunks = [bytearray(chunk_len) for _ in range(num_parity_chunks)]

    for col in range(chunk_len):
        column_bytes = bytes(data_chunks[row][col] for row in range(num_data_chunks))
        encoded = bytes(rsc.encode(column_bytes))  # systematic: message bytes unchanged, parity appended
        for p in range(num_parity_chunks):
            parity_chunks[p][col] = encoded[num_data_chunks + p]

    return data_chunks + [bytes(chunk) for chunk in parity_chunks]


def erasure_decode(available_chunks: dict, num_data_chunks: int, num_parity_chunks: int) -> bytes:
    """
    Reconstruct the original data from whichever chunks are available.

    Args:
        available_chunks: Maps chunk_index (0-based, 0..num_data_chunks +
            num_parity_chunks - 1) to that chunk's bytes. Needs at least
            num_data_chunks entries, of any mix of data/parity indices.

    Returns:
        The original data bytes (padding and length-prefix already stripped).

    Raises:
        InsufficientChunksError: fewer than num_data_chunks are available.
        ChunkCorruptedError: Reed-Solomon reconstruction failed (more
            chunks are actually corrupted/wrong than were marked missing).
    """
    RSCodec, ReedSolomonError = _require_reedsolo()

    total_chunks = num_data_chunks + num_parity_chunks
    if len(available_chunks) < num_data_chunks:
        raise InsufficientChunksError(
            f"Need at least {num_data_chunks} valid chunks to reconstruct the evidence "
            f"payload; only {len(available_chunks)} are available."
        )

    # Fast path: every data chunk is present, no Reed-Solomon needed at all.
    if all(i in available_chunks for i in range(num_data_chunks)):
        padded = b"".join(available_chunks[i] for i in range(num_data_chunks))
    else:
        chunk_len = len(next(iter(available_chunks.values())))
        rsc = RSCodec(num_parity_chunks)
        reconstructed_rows = [bytearray(chunk_len) for _ in range(num_data_chunks)]

        for col in range(chunk_len):
            codeword = bytearray(total_chunks)
            erase_pos = []
            for row in range(total_chunks):
                if row in available_chunks:
                    codeword[row] = available_chunks[row][col]
                else:
                    erase_pos.append(row)

            try:
                decoded = rsc.decode(bytes(codeword), erase_pos=erase_pos)
            except ReedSolomonError as exc:
                raise ChunkCorruptedError(
                    f"Reed-Solomon reconstruction failed at byte offset {col}: {exc}"
                ) from exc
            decoded_msg = decoded[0] if isinstance(decoded, tuple) else decoded

            for row in range(num_data_chunks):
                reconstructed_rows[row][col] = decoded_msg[row]

        padded = b"".join(bytes(row) for row in reconstructed_rows)

    (original_length,) = struct.unpack(">I", padded[:4])
    return padded[4 : 4 + original_length]


def _build_chunk_record(
    evidence_id: bytes, chunk_index: int, total_chunks: int, num_data_chunks: int, chunk_bytes: bytes
) -> bytes:
    if len(evidence_id) != EVIDENCE_ID_SIZE:
        raise EvidenceStorageError(
            f"evidence_id must be exactly {EVIDENCE_ID_SIZE} bytes, got {len(evidence_id)}."
        )
    header = CHUNK_MAGIC + struct.pack(
        CHUNK_HEADER_STRUCT, evidence_id, chunk_index, total_chunks, num_data_chunks, len(chunk_bytes)
    )
    body = header + chunk_bytes
    checksum = hashlib.sha256(body).digest()
    return body + checksum


def embed_chunk_into_frame(
    frame, evidence_id: bytes, chunk_index: int, total_chunks: int, num_data_chunks: int, chunk_bytes: bytes
):
    """
    Like embed_lsb_reference(), but for one erasure-coded chunk: returns
    a COPY of `frame` with the chunk (plus its recording's evidence_id
    and its own index/total/checksum metadata) hidden in the
    least-significant bit of every color channel byte, in raster order.

    `evidence_id` is the recording's own unique evidence ID (16 raw
    bytes) -- see embed_lsb_reference()'s docstring for why this matters:
    it lets discover_evidence_pngs() group chunk PNGs by which recording
    they belong to without depending on their filenames.

    Raises:
        LsbCapacityError: if the frame is too small to hold the record.
    """
    record = _build_chunk_record(evidence_id, chunk_index, total_chunks, num_data_chunks, chunk_bytes)
    record_bits = "".join(f"{byte:08b}" for byte in record)
    num_bits = len(record_bits)

    capacity_bits = frame.size
    if num_bits > capacity_bits:
        raise LsbCapacityError(
            f"Frame is too small to hold chunk {chunk_index}: needs {num_bits} bits, "
            f"frame only has {capacity_bits} channel-byte slots available."
        )

    flat = frame.flatten().copy()
    for i, bit_char in enumerate(record_bits):
        bit = 1 if bit_char == "1" else 0
        flat[i] = (flat[i] & 0xFE) | bit

    return flat.reshape(frame.shape)


def extract_chunk_from_frame(frame):
    """
    Reverse of embed_chunk_into_frame(): read a frame's LSBs, validate
    the chunk record's magic header and checksum, and return
    (evidence_id, chunk_index, total_chunks, num_data_chunks, chunk_bytes).

    Raises:
        ChunkNotFoundError: this frame doesn't contain a valid chunk record.
        ChunkCorruptedError: the record's checksum doesn't match (the
            frame has been altered/recompressed since embedding).
    """
    flat = frame.flatten()

    header_len = len(CHUNK_MAGIC) + struct.calcsize(CHUNK_HEADER_STRUCT)
    header_bits_needed = header_len * 8
    if flat.size < header_bits_needed:
        raise ChunkNotFoundError("Frame is too small to contain a chunk reference header.")

    header_bits = "".join(str(flat[i] & 1) for i in range(header_bits_needed))
    header_bytes = bytes(int(header_bits[i : i + 8], 2) for i in range(0, len(header_bits), 8))

    magic = header_bytes[: len(CHUNK_MAGIC)]
    if magic != CHUNK_MAGIC:
        raise ChunkNotFoundError(
            "No valid Project Crygan chunk reference found in this frame (magic header mismatch)."
        )

    evidence_id, chunk_index, total_chunks, num_data_chunks, payload_length = struct.unpack(
        CHUNK_HEADER_STRUCT, header_bytes[len(CHUNK_MAGIC) :]
    )

    total_record_bytes = header_len + payload_length + CHUNK_CHECKSUM_SIZE
    total_bits_needed = total_record_bytes * 8
    if flat.size < total_bits_needed:
        raise ChunkCorruptedError(
            "Chunk reference is truncated: the declared payload length needs more bits "
            "than this frame contains. The frame may have been resized or corrupted."
        )

    all_bits = "".join(str(flat[i] & 1) for i in range(total_bits_needed))
    record = bytes(int(all_bits[i : i + 8], 2) for i in range(0, len(all_bits), 8))

    body = record[: header_len + payload_length]
    stored_checksum = record[header_len + payload_length :]
    expected_checksum = hashlib.sha256(body).digest()
    if stored_checksum != expected_checksum:
        raise ChunkCorruptedError(
            "Chunk reference failed checksum validation. This reference frame has "
            "likely been modified, recompressed, or corrupted since it was created."
        )

    chunk_bytes = body[header_len:]
    return evidence_id, chunk_index, total_chunks, num_data_chunks, chunk_bytes


def discover_evidence_pngs(directory: str) -> dict:
    """
    Scan every .png file directly inside `directory` and group whatever
    valid chunk / LSB-reference records are found by their embedded
    evidence_id (see EVIDENCE_ID_SIZE above) -- NOT by filename.

    This is the fix for a real, concrete failure mode: chunk/reference
    PNGs used to be located purely by matching the *video's current
    filename* against a naming convention ("<video-base-name>_chunk_
    NNN_of_MMM.png"). That silently breaks the moment the video is
    cropped, trimmed, renamed, or re-saved by any external tool under a
    different filename -- the correct PNGs are still sitting on disk,
    untouched, but nothing finds them anymore. Grouping by the ID
    actually embedded in each PNG's own pixels survives all of that.

    Returns:
        A dict keyed by evidence_id.hex(), each value a dict:
            {
                "chunk_paths": {chunk_index: file_path, ...},
                "total_chunks": int or None,
                "num_data_chunks": int or None,
                "lsb_reference_path": file_path or None,
            }
        Files that aren't readable, aren't PNGs, or don't contain a
        valid Project Crygan record are silently skipped -- exactly like
        the existing per-chunk recovery tolerance in
        VerificationEngine._reconstruct_from_chunks.
    """
    import cv2

    groups: dict = {}

    def _group_for(evidence_id: bytes) -> dict:
        key = evidence_id.hex()
        if key not in groups:
            groups[key] = {
                "chunk_paths": {},
                "total_chunks": None,
                "num_data_chunks": None,
                "lsb_reference_path": None,
            }
        return groups[key]

    if not directory or not os.path.isdir(directory):
        return groups

    for filename in sorted(os.listdir(directory)):
        if not filename.lower().endswith(".png"):
            continue
        path = os.path.join(directory, filename)

        frame = cv2.imread(path)
        if frame is None:
            continue

        try:
            evidence_id, chunk_index, total_chunks, num_data_chunks, _chunk_bytes = extract_chunk_from_frame(frame)
            group = _group_for(evidence_id)
            group["chunk_paths"][chunk_index] = path
            group["total_chunks"] = total_chunks
            group["num_data_chunks"] = num_data_chunks
            continue
        except (ChunkNotFoundError, ChunkCorruptedError):
            pass

        try:
            evidence_id, _reference_bytes = extract_lsb_reference(frame)
            group = _group_for(evidence_id)
            group["lsb_reference_path"] = path
        except (LsbPayloadNotFoundError, LsbPayloadCorruptedError):
            continue

    return groups


def export_evidence_bundle(
    destination_root: str,
    evidence_id_hex: str,
    video_path: str = None,
    companion_path: str = None,
    chunk_paths: dict = None,
    lsb_reference_path: str = None,
    manifest_extra: dict = None,
) -> str:
    """
    Copy whichever evidence artifacts are available for one recording
    into a single, self-contained folder named after that recording's
    evidence_id, ready to hand to someone else as one unit instead of
    several loose files scattered across separate app folders.

    Args:
        destination_root: Parent directory the new folder is created
            under (e.g. config.EVIDENCE_EXPORTS_DIR).
        evidence_id_hex: The recording's evidence_id, as returned by
            EvidenceDatabase / embedded in the chunk & LSB records,
            used verbatim as the folder name.
        video_path: Path to the recorded video, copied in if given.
        companion_path: Path to the .crygan companion file, copied in
            if given.
        chunk_paths: {chunk_index: file_path} as returned by
            discover_evidence_pngs()[...]["chunk_paths"], all copied in
            if given.
        lsb_reference_path: Path to the single LSB reference PNG,
            copied in if given.
        manifest_extra: Optional extra key/value pairs (e.g. a
            verification summary) folded into the written manifest.json.

    Returns:
        The path to the newly created export folder.

    Raises:
        EvidenceStorageError: if the destination folder can't be created
            or a file can't be copied.
    """
    import json
    import shutil

    folder = os.path.join(destination_root, evidence_id_hex)
    try:
        os.makedirs(folder, exist_ok=True)
    except OSError as exc:
        raise EvidenceStorageError(f"Could not create evidence export folder: {exc}") from exc

    manifest = {
        "evidence_id": evidence_id_hex,
        "contents": {},
    }

    def _copy_in(label: str, src_path: str):
        if not src_path or not os.path.exists(src_path):
            manifest["contents"][label] = None
            return
        dest = os.path.join(folder, os.path.basename(src_path))
        try:
            shutil.copy2(src_path, dest)
        except OSError as exc:
            raise EvidenceStorageError(f"Could not copy {src_path} into evidence export folder: {exc}") from exc
        manifest["contents"][label] = os.path.basename(dest)

    _copy_in("video", video_path)
    _copy_in("companion_crygan_file", companion_path)
    _copy_in("lsb_reference_png", lsb_reference_path)

    manifest["contents"]["chunk_pngs"] = []
    for chunk_index in sorted((chunk_paths or {}).keys()):
        src_path = chunk_paths[chunk_index]
        dest = os.path.join(folder, os.path.basename(src_path))
        try:
            shutil.copy2(src_path, dest)
        except OSError as exc:
            raise EvidenceStorageError(f"Could not copy {src_path} into evidence export folder: {exc}") from exc
        manifest["contents"]["chunk_pngs"].append(os.path.basename(dest))

    if manifest_extra:
        manifest.update(manifest_extra)

    manifest_path = os.path.join(folder, "manifest.json")
    try:
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, sort_keys=True)
    except OSError as exc:
        raise EvidenceStorageError(f"Could not write manifest.json in evidence export folder: {exc}") from exc

    return folder


def pick_evenly_spaced_frame_indices(frame_count: int, num_needed: int) -> list:
    """
    Choose `num_needed` distinct frame indices spread as evenly as
    possible across a video of `frame_count` frames, for embedding chunk
    reference frames. Spreading them out (rather than using the first N
    frames) means a single localized edit/cut in the video is less
    likely to land on every single reference frame at once.
    """
    if frame_count <= 0 or num_needed <= 0:
        return []
    if num_needed >= frame_count:
        return list(range(frame_count))

    step = frame_count / num_needed
    used = set()
    for i in range(num_needed):
        idx = min(int(i * step), frame_count - 1)
        while idx in used and idx < frame_count - 1:
            idx += 1
        used.add(idx)
    return sorted(used)
