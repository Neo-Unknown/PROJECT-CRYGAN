"""
crypto_core.py
----------------
Merged module for Project Crygan.

NOTE ON THE FILE NAME: this module was requested as "cryptography.py",
but it is kept as "crypto_core.py" instead. The reason is purely
technical: this file itself needs to `import` the real third-party
`cryptography` package (pyca/cryptography, used for AES-GCM, ECDSA,
PBKDF2, etc.). If this file were named `cryptography.py` and placed in
the same folder as `main.py`, Python would find *this* file first for
any `import cryptography...` statement (since the script's own
directory is searched before installed packages) and shadow the real
package with itself, which would break every encryption/signing call
in the app. Every other requested aspect (no functional changes) is
preserved -- this is the one unavoidable naming deviation.

This module combines, unchanged in behavior:
    * crypto_utils.py  -- SHA-256 helpers + AES-256-GCM encrypt/decrypt
    * keys.py           -- ECC (SECP384R1) key generation/sign/verify
    * hash_chain.py      -- chained SHA-256 frame hashing
    * verification.py    -- the full video verification pipeline

All shared constants/paths live in config.py (a real, separate,
dependency-free module -- see its docstring) and are imported from
there via `import config`, the same way the original standalone files
did. config.py imports nothing from this module or from project_UI.py,
so this remains a one-directional import with no circular dependency.
"""

import base64
import hashlib
import json
import os
import stat
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec

import config
from evidence_storage import (
    extract_payload,
    EvidenceStorageError,
    read_companion_file,
    extract_lsb_reference,
    unpack_reference,
    extract_chunk_from_frame,
    erasure_decode,
    ChunkNotFoundError,
    ChunkCorruptedError,
    InsufficientChunksError,
)

# ==========================================================================
# Originally: crypto_utils.py
# ==========================================================================
"""
crypto_utils.py
----------------
Low-level cryptographic helpers shared across Project Crygan.

This module purposely does NOT know anything about ECC signing keys
(see keys.py for that). It only provides:

    * SHA-256 hashing helpers used by hash_chain.py
    * AES-256-GCM encryption/decryption for evidence metadata, keyed by a
      password/passphrase derived key (PBKDF2-HMAC-SHA256)

Keeping these primitives isolated makes them easy to unit test and reuse.
"""





def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 hex digest of the given bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: bytes) -> bytes:
    """Return the SHA-256 raw digest bytes of the given bytes."""
    return hashlib.sha256(data).digest()


def derive_aes_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from a passphrase and salt via PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=config.AES_KEY_SIZE,
        salt=salt,
        iterations=config.PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_json(payload: dict, passphrase: str) -> bytes:
    """
    Encrypt a JSON-serializable dict with AES-256-GCM.

    Returns a self-contained blob: salt || nonce || ciphertext
    so decryption only requires the passphrase.
    """
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    salt = os.urandom(config.KEY_DERIVATION_SALT_SIZE)
    key = derive_aes_key(passphrase, salt)
    nonce = os.urandom(config.AES_NONCE_SIZE)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    return salt + nonce + ciphertext


def decrypt_json(blob: bytes, passphrase: str) -> dict:
    """Reverse of encrypt_json. Raises ValueError on failure."""
    salt = blob[: config.KEY_DERIVATION_SALT_SIZE]
    nonce = blob[
        config.KEY_DERIVATION_SALT_SIZE : config.KEY_DERIVATION_SALT_SIZE
        + config.AES_NONCE_SIZE
    ]
    ciphertext = blob[config.KEY_DERIVATION_SALT_SIZE + config.AES_NONCE_SIZE :]

    key = derive_aes_key(passphrase, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise ValueError("Failed to decrypt evidence metadata: wrong key or corrupted data") from exc

    return json.loads(plaintext.decode("utf-8"))

# ==========================================================================
# Originally: keys.py
# ==========================================================================
"""
keys.py
-------
Key management for Project Crygan.

Responsibilities:
    * Generate an ECC (SECP384R1) key pair on first launch.
    * Persist the public key in plaintext PEM (safe to share/export).
    * Persist the private key ENCRYPTED at rest using a password-derived
      AES-256-GCM key (PBKDF2-HMAC-SHA256).
    * Provide a clean API for the rest of the application to sign data and
      access the public key, without ever exposing the raw private key
      material outside this module unless explicitly unlocked.

The private key password can be supplied by the user via the Settings UI.
If no password has ever been set, a random machine-local password is
generated and stored with restrictive file permissions as a pragmatic
default for the MVP (documented in the README as a future hardening area).
"""





class KeyManagerError(Exception):
    """Raised for any key management failure."""


class KeyManager:
    """Handles creation, encryption, decryption, and use of the ECC key pair."""

    def __init__(self, password: str):
        """
        Args:
            password: Password used to derive the AES key that protects the
                private key at rest. Callers (the GUI) are responsible for
                collecting this from the user.
        """
        self._password = password
        self._private_key = None  # loaded lazily, kept only in memory

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def ensure_keys_exist(self):
        """Generate a new key pair on first launch if none exists yet."""
        if not os.path.exists(config.PRIVATE_KEY_PATH) or not os.path.exists(
            config.PUBLIC_KEY_PATH
        ):
            self._generate_key_pair()

    def regenerate_keys(self):
        """
        Force-generate a brand new key pair, overwriting whatever is
        currently on disk. Use this when a previous password has been
        forgotten (unlocking the old key is otherwise impossible) or when
        the user explicitly wants to rotate keys.

        This does NOT affect the ability to verify previously-recorded
        videos: verification.py reads the public key embedded inside each
        video's own evidence package, not the currently active key files
        on disk, so old evidence remains verifiable exactly as before.
        Only *future* recordings will be signed with the new key pair.
        """
        self._generate_key_pair()

    def unlock(self):
        """
        Eagerly attempt to decrypt the private key with the password given
        at construction time, and raise immediately if it's wrong.

        Callers (AppState.set_password) use this right after the password
        is entered in Settings, so a wrong password is reported to the user
        right away -- instead of surfacing much later as an InvalidTag
        failure mid-recording (after the camera/writer have already run),
        which previously caused stop_recording() to abort before the
        evidence package was ever embedded.
        """
        self._load_private_key()

    def sign(self, data: bytes) -> bytes:
        """Sign arbitrary bytes with the private key using ECDSA/SHA-384."""
        private_key = self._load_private_key()
        signature = private_key.sign(data, ec.ECDSA(hashes.SHA384()))
        return signature

    def get_public_key_pem(self) -> bytes:
        """Return the public key in PEM format (safe to export/share)."""
        with open(config.PUBLIC_KEY_PATH, "rb") as f:
            return f.read()

    def verify_signature(self, data: bytes, signature: bytes, public_key_pem: bytes) -> bool:
        """Verify a signature against provided data using a public key PEM."""
        try:
            public_key = serialization.load_pem_public_key(public_key_pem)
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA384()))
            return True
        except Exception:
            return False

    def export_public_key(self, destination_path: str):
        """Copy the public key to a user-chosen location."""
        pem = self.get_public_key_pem()
        with open(destination_path, "wb") as f:
            f.write(pem)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _generate_key_pair(self):
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()

        # Persist public key in plaintext PEM.
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with open(config.PUBLIC_KEY_PATH, "wb") as f:
            f.write(public_pem)

        # Serialize the private key unencrypted in memory, then wrap it
        # ourselves with AES-256-GCM so the on-disk format is fully under
        # our control and independent of the `cryptography` library's own
        # PEM-encryption scheme.
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        salt = os.urandom(config.KEY_DERIVATION_SALT_SIZE)
        aes_key = self._derive_key(self._password, salt)

        nonce = os.urandom(config.AES_NONCE_SIZE)
        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, private_bytes, None)

        with open(config.KEY_SALT_PATH, "wb") as f:
            f.write(salt)

        with open(config.PRIVATE_KEY_PATH, "wb") as f:
            f.write(nonce + ciphertext)

        self._restrict_permissions(config.PRIVATE_KEY_PATH)
        self._restrict_permissions(config.KEY_SALT_PATH)

        self._private_key = private_key

    def _load_private_key(self):
        if self._private_key is not None:
            return self._private_key

        if not os.path.exists(config.PRIVATE_KEY_PATH):
            raise KeyManagerError("No private key found. Keys have not been generated yet.")

        with open(config.KEY_SALT_PATH, "rb") as f:
            salt = f.read()

        with open(config.PRIVATE_KEY_PATH, "rb") as f:
            blob = f.read()

        nonce, ciphertext = blob[: config.AES_NONCE_SIZE], blob[config.AES_NONCE_SIZE :]
        aes_key = self._derive_key(self._password, salt)
        aesgcm = AESGCM(aes_key)

        try:
            private_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as exc:
            raise KeyManagerError(
                "Failed to unlock private key. The password may be incorrect "
                "or the key file may be corrupted."
            ) from exc

        private_key = serialization.load_pem_private_key(private_bytes, password=None)
        self._private_key = private_key
        return private_key

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=config.AES_KEY_SIZE,
            salt=salt,
            iterations=config.PBKDF2_ITERATIONS,
        )
        return kdf.derive(password.encode("utf-8"))

    @staticmethod
    def _restrict_permissions(path: str):
        """Best-effort restriction of file permissions to the current user."""
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            # Not all platforms (e.g. Windows) support POSIX chmod bits.
            pass

# ==========================================================================
# Originally: hash_chain.py
# ==========================================================================
"""
hash_chain.py
-------------
Implements a chained SHA-256 hash over recorded video frames.

Chain construction:

    Hash_1 = SHA256(Frame_1)
    Hash_2 = SHA256(Frame_2 || Hash_1)
    Hash_3 = SHA256(Frame_3 || Hash_2)
    ...
    Hash_n = SHA256(Frame_n || Hash_(n-1))

The final hash (Hash_n) commits to every frame and their order: changing,
removing, reordering, or inserting any frame changes the final hash. This
gives Project Crygan a compact, verifiable fingerprint of the entire
recording without needing to store every frame hash (only the final chain
value plus frame count are required for the MVP's tamper check).
"""



class HashChain:
    """Maintains running state for a chained SHA-256 hash over frames."""

    def __init__(self):
        self._previous_hash = b""  # empty for the very first frame
        self._frame_count = 0

    def add_frame(self, frame_bytes: bytes) -> bytes:
        """
        Feed the next frame into the chain.

        Args:
            frame_bytes: Raw bytes of the frame (e.g. encoded JPEG bytes or
                the raw numpy buffer, as long as it is used consistently).

        Returns:
            The new running hash (raw bytes) after including this frame.
        """
        combined = frame_bytes + self._previous_hash
        new_hash = sha256_bytes(combined)
        self._previous_hash = new_hash
        self._frame_count += 1
        return new_hash

    @property
    def frame_count(self) -> int:
        return self._frame_count

    @property
    def final_hash_hex(self) -> str:
        """Hex representation of the final chain value."""
        return self._previous_hash.hex()

    def reset(self):
        """Reset the chain to start recording a fresh video."""
        self._previous_hash = b""
        self._frame_count = 0


def recompute_chain_from_frames(frames) -> str:
    """
    Recompute a chain hash from an iterable of frame byte buffers.

    Used during verification to confirm that the frames extracted from a
    video still produce the same final hash that was recorded in the
    embedded evidence package.
    """
    chain = HashChain()
    for frame_bytes in frames:
        chain.add_frame(frame_bytes)
    return chain.final_hash_hex


def compute_chain_from_video(video_path: str):
    """
    Read every frame back out of a video file (as decoded by OpenCV) and
    compute the chained SHA-256 hash over them.

    IMPORTANT: this is used both right after recording (recorder.py,
    once the file has been fully written) and again during verification
    (verification.py). Using the same *decoded* frames on both ends is
    what makes the two hashes comparable at all. Video codecs -- even
    ones that claim to be lossless -- are free to re-pack pixel data,
    convert color spaces, or otherwise return bytes that differ from the
    raw camera buffer that existed before encoding. Hashing the raw
    pre-encode camera bytes at capture time and comparing that against
    post-decode bytes at verify time would fail on every single
    recording, tampered or not, since the codec itself changes the bytes.
    Routing both capture-time and verify-time hashing through this one
    function guarantees they're doing exactly the same thing.

    CROSS-PLATFORM CAVEAT: even with that guarantee, this does not make
    verification fully deterministic *across different machines*. When no
    backend is specified, OpenCV silently picks whatever platform-default
    backend is installed (e.g. MSMF on Windows, AVFoundation on macOS,
    V4L2/GStreamer on Linux), and different backends -- or even different
    builds/versions of the same backend -- can perform YUV->RGB color
    conversion slightly differently, producing different decoded pixel
    bytes for an identical, untampered file. That would surface as a
    false-positive hash mismatch during verification on a different
    machine than the one that recorded the video.

    To reduce (not eliminate) this, we explicitly request the FFmpeg
    backend here rather than letting OpenCV choose one implicitly, since
    FFmpeg is the most consistently available and consistently-behaved
    backend across Windows/macOS/Linux OpenCV builds. This does not fully
    guarantee bit-identical decoding on every machine (different FFmpeg
    versions can still diverge), so for the strongest guarantees,
    evidence should ideally be verified with the same OpenCV/FFmpeg
    versions used to record it -- but forcing a single, explicit backend
    removes the largest and most common source of divergence.

    Returns:
        (final_hash_hex, frame_count)
    """
    import cv2

    # Prefer the FFmpeg backend explicitly (see caveat above). Some
    # OpenCV builds are compiled without FFmpeg support, in which case
    # cv2.VideoCapture(..., cv2.CAP_FFMPEG) simply fails to open and we
    # fall back to whatever default backend is available, rather than
    # hard-failing outright.
    capture = cv2.VideoCapture(video_path, cv2.CAP_FFMPEG)
    if not capture.isOpened():
        capture = cv2.VideoCapture(video_path)
    if not capture.isOpened():
        raise RuntimeError(f"Could not open video file for hashing: {video_path}")

    chain = HashChain()
    try:
        while True:
            success, frame = capture.read()
            if not success:
                break
            chain.add_frame(frame.tobytes())
    finally:
        capture.release()

    return chain.final_hash_hex, chain.frame_count


# ==========================================================================
# Frame-level Merkle commitment & perceptual hashing (new -- not part of
# the original modules; see config.py's "Frame-level tamper localization &
# perceptual hashing" section for the full rationale)
# ==========================================================================


def _merkle_parent(left: bytes, right: bytes) -> bytes:
    return sha256_bytes(left + right)


def build_merkle_tree(leaf_hashes: list) -> list:
    """
    Build a binary Merkle tree over a list of leaf hashes.

    Returns a list of levels: levels[0] is the leaves themselves, and
    levels[-1] is a single-element list containing the root. An odd node
    out at any level is paired with itself (the standard, widely-used
    convention -- as used by e.g. Bitcoin's transaction Merkle trees).

    An empty leaf list produces a root of SHA-256(b""), so the function
    always returns a well-defined tree/root rather than raising.
    """
    if not leaf_hashes:
        return [[sha256_bytes(b"")]]
    levels = [list(leaf_hashes)]
    current = levels[0]
    while len(current) > 1:
        next_level = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else current[i]
            next_level.append(_merkle_parent(left, right))
        levels.append(next_level)
        current = next_level
    return levels


def merkle_root(leaf_hashes: list) -> bytes:
    """Convenience wrapper: build the tree and return just the root bytes."""
    return build_merkle_tree(leaf_hashes)[-1][0]


def merkle_proof(levels: list, index: int) -> list:
    """
    Build an inclusion proof for the leaf at `index`, given the full set
    of levels returned by build_merkle_tree().

    Returns a list of (sibling_hash, sibling_is_left) tuples, ordered from
    the leaf up to (but not including) the root. Feed this to
    verify_merkle_proof() along with the leaf hash and root to confirm
    that specific leaf was part of the committed tree -- without needing
    any of the other leaves.
    """
    proof = []
    idx = index
    for level in levels[:-1]:
        is_right = idx % 2 == 1
        sibling_idx = idx - 1 if is_right else idx + 1
        if sibling_idx >= len(level):
            sibling_idx = idx  # this node was paired with itself (odd node out)
        proof.append((level[sibling_idx], is_right))
        idx //= 2
    return proof


def verify_merkle_proof(leaf_hash: bytes, proof: list, root: bytes) -> bool:
    """Recompute the root from `leaf_hash` and `proof`; compare to `root`."""
    computed = leaf_hash
    for sibling_hash, sibling_is_left in proof:
        if sibling_is_left:
            computed = _merkle_parent(sibling_hash, computed)
        else:
            computed = _merkle_parent(computed, sibling_hash)
    return computed == root


def hamming_distance_bytes(a: bytes, b: bytes) -> int:
    """Bit-level Hamming distance between two equal-length byte strings."""
    if len(a) != len(b):
        raise ValueError("Hamming distance requires equal-length byte strings")
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def sample_fingerprint(perceptual_hashes: list, num_samples: int = None) -> bytes:
    """
    Build a fixed-length "video fingerprint" for the local evidence
    registry (see config.py's "Local perceptual-hash evidence registry"
    section) by sampling num_samples perceptual hashes at evenly-spaced
    RELATIVE positions through the frame sequence -- not fixed absolute
    frame indices -- so two videos with slightly different frame
    counts/frame rates (e.g. an original vs. a transcoded copy) still
    land on approximately the same visual content at each sample point.

    Returns num_samples * PERCEPTUAL_HASH_SIZE_BYTES raw bytes. An empty
    input returns b"". Recordings shorter than num_samples still produce
    a usable (if less discriminating) fingerprint -- sample positions
    simply repeat the nearest available frame rather than raising.
    """
    if not perceptual_hashes:
        return b""
    num_samples = num_samples or config.FINGERPRINT_SAMPLE_COUNT
    n = len(perceptual_hashes)
    if num_samples <= 1 or n == 1:
        indices = [0] * max(num_samples, 1)
    else:
        indices = [round(i * (n - 1) / (num_samples - 1)) for i in range(num_samples)]
    return b"".join(perceptual_hashes[i] for i in indices)


def compare_fingerprints(fingerprint_a: bytes, fingerprint_b: bytes, hash_size_bytes: int = None) -> float:
    """
    Average per-sample Hamming distance (in bits) between two
    fingerprints built by sample_fingerprint() with the same
    num_samples/hash size. Lower means more similar; 0 means identical at
    every sampled position.

    Raises ValueError if the two fingerprints aren't the same length
    (i.e. weren't built with matching parameters, or one is empty) --
    callers should treat that as "not comparable," not "no match."
    """
    hash_size_bytes = hash_size_bytes or config.PERCEPTUAL_HASH_SIZE_BYTES
    if len(fingerprint_a) == 0 or len(fingerprint_b) == 0:
        raise ValueError("Cannot compare an empty fingerprint")
    if len(fingerprint_a) != len(fingerprint_b) or len(fingerprint_a) % hash_size_bytes != 0:
        raise ValueError("Fingerprints must be equal length and a multiple of the per-frame hash size")
    num_samples = len(fingerprint_a) // hash_size_bytes
    total_distance = 0
    for i in range(num_samples):
        a = fingerprint_a[i * hash_size_bytes : (i + 1) * hash_size_bytes]
        b = fingerprint_b[i * hash_size_bytes : (i + 1) * hash_size_bytes]
        total_distance += hamming_distance_bytes(a, b)
    return total_distance / num_samples


class PerceptualHashUnavailable(Exception):
    """
    Raised if perceptual hashing genuinely can't run (e.g. cv2 missing).
    In normal installs this should never happen: unlike the first version
    of this feature, perceptual hashing no longer needs any package beyond
    what the app already hard-requires (cv2, numpy) -- see
    compute_perceptual_hash()'s docstring for why.
    """


def compute_perceptual_hash(frame_bgr) -> bytes:
    """
    Compute a 64-bit perceptual difference-hash (dHash) for a single
    decoded video frame (OpenCV's usual BGR numpy array), returned as 8
    raw bytes.

    Uses dHash (resize + adjacent-pixel comparison) rather than the
    DCT-based pHash this feature originally shipped with. dHash needs
    only cv2 and numpy -- both already hard requirements of this app --
    instead of pulling in the `imagehash` package's own dependency chain
    (Pillow, scipy, PyWavelets) for a capability the app can get for
    free. Detection quality is comparable for this app's purpose
    (recognizing "still the same frame, just recompressed").
    """
    import cv2
    import numpy as np

    hash_size = config.PERCEPTUAL_HASH_SIZE_BYTES  # 8 -> 8x8 = 64 bits
    gray = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2GRAY)
    resized = cv2.resize(gray, (hash_size + 1, hash_size), interpolation=cv2.INTER_AREA)
    diff_bits = resized[:, 1:] > resized[:, :-1]  # 8x8 boolean array, 64 bits
    return np.packbits(diff_bits).tobytes()


def compute_full_chain_from_video(video_path: str, include_perceptual: bool = None):
    """
    Like compute_chain_from_video(), but additionally returns everything
    needed for Merkle-based tamper localization and perceptual-hash
    transcode tolerance:

        * the same linear chained final_hash_hex + frame_count as before
          (kept for backward compatibility with recordings/verification
          logic made before this feature existed)
        * frame_leaf_hashes: list of per-frame SHA-256 hashes, UNCHAINED
          (i.e. plain sha256(frame_bytes) each, not folded into the
          previous frame's hash) -- these are the Merkle tree leaves
        * merkle_root_hex: the Merkle root over frame_leaf_hashes
        * perceptual_hashes: list of 8-byte pHash values, one per frame,
          or None if include_perceptual is False or the optional
          `imagehash` package isn't installed

    Deliberately a separate function from compute_chain_from_video() (with
    its own frame-decode loop) rather than a modified version of it, so
    the original, already-relied-upon linear-chain code path is completely
    untouched by this addition.

    Uses the same FFmpeg-backend-first decode strategy, for the same
    reasons documented on compute_chain_from_video() -- capture-time and
    verify-time calls MUST go through matching decode logic for hashes to
    be comparable at all.

    Returns a dict with keys: final_hash_hex, frame_count, merkle_root_hex,
    frame_leaf_hashes, perceptual_hashes.
    """
    import cv2

    if include_perceptual is None:
        include_perceptual = getattr(config, "PERCEPTUAL_HASHING_ENABLED", True)

    capture = cv2.VideoCapture(video_path, cv2.CAP_FFMPEG)
    if not capture.isOpened():
        capture = cv2.VideoCapture(video_path)
    if not capture.isOpened():
        raise RuntimeError(f"Could not open video file for hashing: {video_path}")

    chain = HashChain()
    leaf_hashes = []
    perceptual_hashes = [] if include_perceptual else None
    try:
        while True:
            success, frame = capture.read()
            if not success:
                break
            frame_bytes = frame.tobytes()
            chain.add_frame(frame_bytes)
            leaf_hashes.append(sha256_bytes(frame_bytes))
            if perceptual_hashes is not None:
                perceptual_hashes.append(compute_perceptual_hash(frame))
    finally:
        capture.release()

    return {
        "final_hash_hex": chain.final_hash_hex,
        "frame_count": chain.frame_count,
        "merkle_root_hex": merkle_root(leaf_hashes).hex(),
        "frame_leaf_hashes": leaf_hashes,
        "perceptual_hashes": perceptual_hashes,
    }

# ==========================================================================
# RFC 3161 trusted timestamping (new -- not part of the original modules)
# ==========================================================================
"""
Independent, third-party attestation of *when* the final frame hash chain
value existed, obtained from a public RFC 3161 Time-Stamp Authority (TSA)
over the network at the moment a recording finishes.

WHY THIS EXISTS: without it, the only claim about capture time is
evidence_payload["timestamp"], built from this machine's local system clock
(see project_UI.py's VideoRecorder.stop_recording). A local clock can be
changed by anyone before recording, so that claim is entirely self-asserted
and proves nothing on its own. A trusted timestamp fixes that for one
specific, narrower claim: "this exact final_hash value existed no later
than <TSA-attested time>", independently signed by a third party's server
clock -- not this machine's.

WHAT THIS DOES NOT DO: it does not replace the local timestamp (which still
records the *claimed* recording wall-clock time/date/location), and it does
not prove the recording itself is authentic -- only that the specific hash
value was submitted to the TSA by the stated time. By default it also does
not perform full PKI chain-of-trust validation of the TSA's certificate up
to a root CA -- see verify_trusted_timestamp()'s docstring for how to add
that via config.TSA_CA_CERT_PATH.

Requires the optional `rfc3161ng` package:
    pip install rfc3161ng
Purely additive, matching the pattern used for the optional `reedsolo`
Reed-Solomon chunks elsewhere in this app (see evidence_storage.py): if the
package isn't installed, or the TSA is unreachable (offline recording,
firewall, TSA downtime), timestamping is simply unavailable. Recording and
verification always proceed without it -- this never blocks or invalidates
either one.
"""


class TimestampError(Exception):
    """Raised when requesting or verifying an RFC 3161 timestamp fails."""


def _require_rfc3161ng():
    try:
        import rfc3161ng
    except ImportError as exc:
        raise TimestampError(
            "The optional 'rfc3161ng' package is not installed, so trusted "
            "timestamping is unavailable for this recording/verification. "
            "Install it with:\n    pip install rfc3161ng"
        ) from exc
    return rfc3161ng


def request_trusted_timestamp(data_hash: bytes, tsa_url: str = None, timeout: float = None) -> bytes:
    """
    Ask a public RFC 3161 Time-Stamp Authority to sign a token attesting
    that `data_hash` (the raw SHA-256 final frame-hash-chain digest, NOT
    its hex string) existed at the TSA's current time.

    Returns the raw DER-encoded TimeStampToken bytes. The caller should
    store these (base64-encoded, alongside which hash they cover) inside
    the evidence payload, and make sure that happens BEFORE the payload is
    signed with the recorder's own ECC key -- that way the token can't be
    swapped out later without also invalidating the ECC signature.

    Raises TimestampError if the package is missing, the TSA can't be
    reached, or the TSA's response doesn't check out (message imprint
    mismatch, bad signature, etc.). Callers that want timestamping to be
    optional (recommended -- see this section's module docstring) should
    catch TimestampError and simply proceed without a token.
    """
    rfc3161ng = _require_rfc3161ng()

    tsa_url = tsa_url or config.TSA_URL
    timeout = timeout if timeout is not None else config.TSA_TIMEOUT_SECONDS

    timestamper = rfc3161ng.RemoteTimestamper(
        tsa_url,
        hashname=config.TSA_HASH_ALGORITHM,
        # Ask the TSA to embed its own signing certificate in the response,
        # so the token is self-contained and verifiable later without a
        # separate network call to fetch it. (See verify_trusted_timestamp
        # for the trust caveat this implies.)
        include_tsa_certificate=True,
        timeout=timeout,
    )
    try:
        return timestamper.timestamp(digest=data_hash)
    except rfc3161ng.TimestampingError as exc:
        raise TimestampError(f"RFC 3161 timestamp request to {tsa_url} failed: {exc}") from exc
    except Exception as exc:
        raise TimestampError(f"RFC 3161 timestamp request to {tsa_url} failed: {exc}") from exc


def verify_trusted_timestamp(data_hash: bytes, token_bytes: bytes, tsa_ca_cert_path: str = None):
    """
    Verify an RFC 3161 timestamp token against the given raw hash digest.

    Confirms:
        * the token's message imprint matches `data_hash` exactly (i.e.
          this token was issued FOR this specific hash, not some other one)
        * the token's signature is valid under the certificate it carries
          (or, if `tsa_ca_cert_path` is given, under that pinned cert
          instead -- see the trust caveat below)

    Returns (is_valid, tsa_timestamp_utc, error):
        is_valid           -- bool
        tsa_timestamp_utc  -- timezone-aware datetime.datetime, or None
        error              -- str describing the failure, or None

    TRUST CAVEAT: by default this only proves the token is *internally
    consistent* -- correctly signed by whatever certificate it carries --
    which is the same category of limitation as the embedded-public-key
    issue elsewhere in this app (VerificationEngine trusting the payload's
    own public_key_pem). To actually pin trust to one specific TSA rather
    than "any certificate that happens to be embedded in the token", set
    config.TSA_CA_CERT_PATH to a locally stored copy of that TSA's
    certificate (PEM), obtained once out-of-band (e.g. downloaded from the
    TSA operator's site over TLS and saved alongside the app), and pass it
    through here or via that config value. This checks the token's
    signature against that specific pinned certificate instead of trusting
    whatever the token itself claims to be signed by.
    """
    rfc3161ng = _require_rfc3161ng()

    cert_bytes = None
    cert_path = tsa_ca_cert_path or config.TSA_CA_CERT_PATH
    if cert_path:
        try:
            with open(cert_path, "rb") as fh:
                cert_bytes = fh.read()
        except OSError as exc:
            return False, None, f"Could not read pinned TSA certificate at {cert_path}: {exc}"

    try:
        # certificate=b"" (rather than None) tells rfc3161ng to extract the
        # certificate embedded in the token itself when no pinned cert was
        # supplied above -- see the trust caveat in this function's
        # docstring for what that does and doesn't prove.
        rfc3161ng.check_timestamp(
            token_bytes,
            certificate=cert_bytes if cert_bytes is not None else b"",
            digest=data_hash,
            hashname=config.TSA_HASH_ALGORITHM,
        )
    except Exception as exc:
        return False, None, f"Timestamp token verification failed: {exc}"

    try:
        tsa_timestamp_utc = rfc3161ng.get_timestamp(token_bytes, naive=False)
    except Exception as exc:
        return False, None, f"Timestamp token verified but its genTime could not be read: {exc}"

    return True, tsa_timestamp_utc, None

# ==========================================================================
# Originally: verification.py
# ==========================================================================
"""
verification.py
----------------
Implements the verification workflow for a previously recorded video:

    1. Extract the embedded encrypted evidence package (evidence_storage.py).
    2. Decrypt it with a user-supplied passphrase (crypto_utils.py).
    3. Verify the ECC digital signature over the evidence payload (keys.py).
    4. Re-read every frame from the video and recompute the chained
       SHA-256 hash (hash_chain.py), then compare it against the hash
       recorded at capture time.
    5. If a steganographic LSB reference PNG is also supplied, extract its
       hidden hash+signature and cross-check it against steps 3-4 as an
       extra, independent confirmation (see evidence_storage.py's "LSB"
       section). This step is entirely optional and additive: omitting a
       reference frame does not affect overall_integrity_ok, which still
       reflects only steps 1-4, exactly as before this feature existed.
    6. Produce a structured VerificationResult describing exactly what
       passed and what failed, suitable for both the GUI and PDF report.
"""




class VerificationResult:
    """Structured result of a verification run, for GUI and report use."""

    def __init__(self):
        self.evidence_found = False
        self.companion_file_checked = False
        self.companion_file_used = False
        self.decryption_ok = False
        self.signature_ok = False
        self.chain_ok = False

        self.recorded_frame_count = None
        self.recomputed_frame_count = None
        self.recorded_final_hash = None
        self.recomputed_final_hash = None

        # LSB reference cross-check (optional -- None means "not checked",
        # as opposed to True/False which mean "checked and passed/failed").
        # This intentionally does NOT factor into overall_integrity_ok:
        # it's a bonus corroborating signal, not a requirement, so videos
        # verified without a reference frame behave exactly as before.
        self.lsb_reference_checked = False
        self.lsb_reference_ok = None
        self.lsb_reference_evidence_id = None

        # Reed-Solomon erasure-coded chunk recovery (see evidence_storage.py).
        # Only ever comes into play as a FALLBACK when the primary
        # tail-appended evidence payload could not be found/read at all --
        # it never overrides a successfully-read primary payload.
        self.chunk_recovery_attempted = False
        self.chunk_recovery_ok = False
        self.chunk_recovery_chunks_used = 0
        self.chunk_recovery_chunks_available = 0
        self.chunk_recovery_evidence_id = None

        # RFC 3161 trusted timestamp cross-check (see crypto_core.py's
        # "RFC 3161 trusted timestamping" section). Like the LSB reference
        # above, this is a bonus, independent corroborating signal -- it
        # intentionally does NOT factor into overall_integrity_ok, so
        # recordings made without network access, or before this feature
        # existed, still verify exactly as before.
        self.timestamp_checked = False
        self.timestamp_ok = None
        self.tsa_timestamp_utc = None  # ISO 8601 string, if timestamp_ok
        self.tsa_url = None

        # Merkle tree / per-frame tamper localization + perceptual hashing
        # (see crypto_core.py's "Frame-level Merkle commitment & perceptual
        # hashing" section). Like the LSB/timestamp checks above, this is a
        # bonus, independent signal layered on top of the original chain_ok
        # check -- it never changes overall_integrity_ok on its own; its
        # purpose is to make a chain_ok=False failure more informative.
        self.merkle_checked = False
        self.merkle_ok = None
        self.tampered_frame_indices = []       # ALL frame indices whose exact hash differs
        self.tampered_frame_indices_truncated = False
        # Per-frame split of the above, when perceptual hashing is available:
        # each differing frame is individually classified rather than judged
        # as a single all-or-nothing verdict, so a realistic mixed case (some
        # frames just recompressed, one frame genuinely altered) is reported
        # as such instead of collapsing to one aggregate answer.
        self.transcoded_frame_indices = []     # differing frames classified as
                                                # "just recompression" (small
                                                # perceptual distance)
        self.content_altered_frame_indices = []  # differing frames classified
                                                  # as genuinely changed content
                                                  # (large perceptual distance,
                                                  # or perceptual hash unavailable)
        self.perceptual_hashing_available = None

        # Local perceptual-hash registry fallback (see config.py's "Local
        # perceptual-hash evidence registry" section). Only ever set when
        # NO evidence could be extracted from the file at all (primary
        # AND chunk-recovery both failed) -- a successfully-read
        # file-embedded payload is never second-guessed by this fallback.
        self.registry_lookup_attempted = False
        self.registry_match_used = False
        self.registry_match_evidence_id = None
        self.registry_match_average_distance = None

        self.evidence_payload = None  # decrypted dict, if available
        self.failure_reasons = []

    @property
    def overall_integrity_ok(self) -> bool:
        return self.evidence_found and self.decryption_ok and self.signature_ok and self.chain_ok

    @property
    def evidence_source(self) -> str:
        """
        Single, authoritative statement of exactly how (or whether) the
        evidence used for this verification was obtained -- so this
        never has to be pieced together by a reader from several
        separate conditional flags. Reflects exactly one of the
        mutually-exclusive recovery outcomes, in the same priority order
        VerificationEngine.verify() actually tries them in (see
        evidence_storage.py's "Companion .crygan evidence package"
        section): file-embedded, companion package, Reed-Solomon
        reconstruction, local registry, or not found at all. Always
        shown first/prominently in reports and on-screen results so a
        reader has complete transparency about provenance strength
        before looking at anything else.
        """
        if not self.evidence_found:
            return "NOT FOUND -- no evidence could be recovered from the file, companion package, or local registry"
        if self.companion_file_used:
            return "Companion .crygan evidence package (video's own embedded copy was missing/unreadable)"
        if self.chunk_recovery_ok:
            return "Reed-Solomon chunk reconstruction (primary embedded copy was missing/corrupted)"
        if self.registry_match_used:
            return (
                f"Local out-of-band registry match (evidence_id={self.registry_match_evidence_id}, "
                f"avg. perceptual distance={self.registry_match_average_distance:.1f}/64 bits) "
                "-- weaker provenance than the other sources above; same-machine only"
            )
        return "Embedded directly in the video file (primary path)"

    def add_failure(self, reason: str):
        self.failure_reasons.append(reason)

    def to_dict(self) -> dict:
        return {
            "evidence_source": self.evidence_source,
            "evidence_found": self.evidence_found,
            "companion_file_checked": self.companion_file_checked,
            "companion_file_used": self.companion_file_used,
            "decryption_ok": self.decryption_ok,
            "signature_ok": self.signature_ok,
            "chain_ok": self.chain_ok,
            "overall_integrity_ok": self.overall_integrity_ok,
            "recorded_frame_count": self.recorded_frame_count,
            "recomputed_frame_count": self.recomputed_frame_count,
            "recorded_final_hash": self.recorded_final_hash,
            "recomputed_final_hash": self.recomputed_final_hash,
            "lsb_reference_checked": self.lsb_reference_checked,
            "lsb_reference_ok": self.lsb_reference_ok,
            "lsb_reference_evidence_id": self.lsb_reference_evidence_id,
            "chunk_recovery_attempted": self.chunk_recovery_attempted,
            "chunk_recovery_ok": self.chunk_recovery_ok,
            "chunk_recovery_chunks_used": self.chunk_recovery_chunks_used,
            "chunk_recovery_chunks_available": self.chunk_recovery_chunks_available,
            "chunk_recovery_evidence_id": self.chunk_recovery_evidence_id,
            "timestamp_checked": self.timestamp_checked,
            "timestamp_ok": self.timestamp_ok,
            "tsa_timestamp_utc": self.tsa_timestamp_utc,
            "tsa_url": self.tsa_url,
            "merkle_checked": self.merkle_checked,
            "merkle_ok": self.merkle_ok,
            "tampered_frame_indices": self.tampered_frame_indices,
            "tampered_frame_indices_truncated": self.tampered_frame_indices_truncated,
            "transcoded_frame_indices": self.transcoded_frame_indices,
            "content_altered_frame_indices": self.content_altered_frame_indices,
            "perceptual_hashing_available": self.perceptual_hashing_available,
            "registry_lookup_attempted": self.registry_lookup_attempted,
            "registry_match_used": self.registry_match_used,
            "registry_match_evidence_id": self.registry_match_evidence_id,
            "registry_match_average_distance": self.registry_match_average_distance,
            "failure_reasons": self.failure_reasons,
        }


class VerificationEngine:
    """Runs the full verification pipeline against a video file."""

    def verify(
        self,
        video_path: str,
        evidence_passphrase: str,
        stego_reference_path: str = None,
        stego_chunk_paths: list = None,
        registry_candidates: list = None,
        companion_path: str = None,
    ) -> VerificationResult:
        result = VerificationResult()

        # ------------------------------------------------------------
        # Step 1: extract embedded evidence package (primary path)
        # ------------------------------------------------------------
        encrypted_blob = None
        try:
            encrypted_blob = extract_payload(video_path)
            result.evidence_found = True
        except EvidenceStorageError as exc:
            result.add_failure(str(exc))

        # ------------------------------------------------------------
        # Step 1a (fallback): the companion .crygan sidecar file (see
        # evidence_storage.py's "Companion .crygan evidence file" section).
        # This is the recovery path that actually matters for handing
        # evidence to someone else -- a court, a forensic lab, another
        # investigator's machine -- since (unlike the local registry
        # below) it travels WITH the video as an ordinary file, and
        # (unlike in-file embedding) it isn't destroyed by transcoding.
        # Ranked above chunk recovery and the registry: if present, it's
        # a complete, simple, self-contained recovery, not a partial
        # reconstruction or a same-machine-only fallback.
        # ------------------------------------------------------------
        if encrypted_blob is None and companion_path:
            result.companion_file_checked = True
            try:
                encrypted_blob = read_companion_file(companion_path)
                result.evidence_found = True
                result.companion_file_used = True
                result.add_failure(
                    "Note: the primary embedded evidence package was missing or "
                    "unreadable (consistent with the video having been transcoded/"
                    "re-encoded after recording). The companion .crygan file was used "
                    "to recover the evidence instead -- this still requires both files "
                    "(video + .crygan) to be kept together."
                )
            except EvidenceStorageError as exc:
                result.add_failure(f"Companion .crygan file recovery failed: {exc}")

        # ------------------------------------------------------------
        # Step 1b (fallback): the primary tail-appended payload could not
        # be found/read at all -- e.g. the file was truncated, re-muxed,
        # or the trailing bytes were otherwise stripped or corrupted.
        # Rather than giving up on recovering ANYTHING, try to
        # reconstruct the same encrypted blob from whichever
        # Reed-Solomon-coded chunk reference frames are still available
        # (see evidence_storage.py). This only ever runs when the primary
        # path failed; a successfully-read primary payload is never
        # second-guessed by this fallback.
        # ------------------------------------------------------------
        if encrypted_blob is None and stego_chunk_paths:
            result.chunk_recovery_attempted = True
            try:
                encrypted_blob = self._reconstruct_from_chunks(stego_chunk_paths, result)
                result.evidence_found = True
                result.chunk_recovery_ok = True
                result.add_failure(
                    "Note: the primary embedded evidence package was missing or "
                    "corrupted, but was successfully RECONSTRUCTED from "
                    f"{result.chunk_recovery_chunks_used} of "
                    f"{result.chunk_recovery_chunks_available} available Reed-Solomon "
                    "reference chunk frames."
                )
            except EvidenceStorageError as exc:
                result.add_failure(f"Chunk-based evidence recovery also failed: {exc}")

        # ------------------------------------------------------------
        # Step 1c (fallback): NEITHER the primary tail-appended payload
        # NOR the Reed-Solomon chunk reconstruction could recover
        # anything -- this typically means the video was transcoded/
        # re-encoded after recording, which rewrites the container from
        # scratch and strips everything embedded in it (see config.py's
        # "Local perceptual-hash evidence registry" section for why no
        # in-file technique can survive that).
        #
        # As a last resort, try to recognize this video by content alone
        # against this machine's own local recording registry, and use
        # ITS independently-stored copy of the evidence instead. This is
        # deliberately the last thing tried, and is clearly flagged below
        # as weaker provenance than file-embedded evidence.
        # ------------------------------------------------------------
        if encrypted_blob is None and registry_candidates:
            result.registry_lookup_attempted = True
            try:
                probe = compute_full_chain_from_video(video_path, include_perceptual=True)
                probe_fingerprint = (
                    sample_fingerprint(probe["perceptual_hashes"]) if probe["perceptual_hashes"] else b""
                )
                best_candidate, best_distance = None, None
                for candidate in registry_candidates:
                    try:
                        candidate_fp = base64.b64decode(candidate["fingerprint_b64"])
                        distance = compare_fingerprints(probe_fingerprint, candidate_fp)
                    except (ValueError, KeyError, TypeError):
                        continue  # not comparable (empty/mismatched/malformed) -- skip, don't fail
                    if best_distance is None or distance < best_distance:
                        best_candidate, best_distance = candidate, distance

                if (
                    best_candidate is not None
                    and best_distance <= config.FINGERPRINT_AVERAGE_DISTANCE_THRESHOLD_BITS
                ):
                    encrypted_blob = base64.b64decode(best_candidate["encrypted_payload_b64"])
                    result.evidence_found = True
                    result.registry_match_used = True
                    result.registry_match_evidence_id = best_candidate.get("evidence_id")
                    result.registry_match_average_distance = best_distance
                    result.add_failure(
                        "Note: no evidence package could be extracted from this file at all "
                        "(consistent with the video having been re-encoded/transcoded after "
                        f"recording). A closely matching entry (avg. perceptual distance "
                        f"{best_distance:.1f}/64 bits per sample) was found in this machine's "
                        "LOCAL recording registry and its independently-stored evidence copy "
                        "was used instead. This is WEAKER provenance than file-embedded "
                        "evidence: it depends on trusting this specific Crygan installation's "
                        "own local database, not solely the cryptographic signature chain -- "
                        "treat accordingly, and prefer file-embedded verification whenever "
                        "the original, unprocessed recording is available."
                    )
            except Exception as exc:
                result.add_failure(f"Local registry fallback lookup error: {exc}")

        if encrypted_blob is None:
            return result

        # ------------------------------------------------------------
        # Step 2: decrypt evidence metadata
        # ------------------------------------------------------------
        try:
            payload = decrypt_json(encrypted_blob, evidence_passphrase)
            result.decryption_ok = True
            result.evidence_payload = payload
        except ValueError as exc:
            result.add_failure(f"Decryption failed: {exc}")
            return result

        result.recorded_frame_count = payload.get("frame_hash_chain", {}).get("frame_count")
        result.recorded_final_hash = payload.get("frame_hash_chain", {}).get("final_hash")

        # ------------------------------------------------------------
        # Step 3: verify digital signature
        # ------------------------------------------------------------
        signature_hex = None
        try:
            signature_hex = payload.pop("signature_hex")
            public_key_pem = payload.pop("public_key_pem")
            canonical_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

            key_manager = KeyManager(password="")  # not unlocking private key; verify-only
            signature_valid = key_manager.verify_signature(
                canonical_bytes, bytes.fromhex(signature_hex), public_key_pem.encode("utf-8")
            )
            result.signature_ok = signature_valid
            if not signature_valid:
                result.add_failure(
                    "Digital signature verification failed. The evidence metadata "
                    "may have been altered after recording, or a different key was used."
                )
        except Exception as exc:
            result.add_failure(f"Signature verification error: {exc}")

        # ------------------------------------------------------------
        # Step 4: recompute frame hash chain from the actual video
        # ------------------------------------------------------------
        recorded_chain_info = payload.get("frame_hash_chain", {})
        has_merkle_data = bool(recorded_chain_info.get("merkle_root")) and bool(
            recorded_chain_info.get("frame_leaf_hashes_b64")
        )
        has_perceptual_data = bool(recorded_chain_info.get("perceptual_hashes_b64"))
        full_chain = None
        try:
            if has_merkle_data:
                # One decode pass gets us the linear chain AND everything
                # needed for Step 4c's tamper localization below, instead
                # of decoding the whole video twice.
                full_chain = compute_full_chain_from_video(video_path, include_perceptual=has_perceptual_data)
                recomputed_hash = full_chain["final_hash_hex"]
                recomputed_count = full_chain["frame_count"]
            else:
                # Older recordings (made before this feature existed) have
                # no Merkle data in their payload -- fall back to the
                # original, cheaper linear-only recomputation.
                recomputed_hash, recomputed_count = self._recompute_chain(video_path)

            result.recomputed_final_hash = recomputed_hash
            result.recomputed_frame_count = recomputed_count

            result.chain_ok = (
                recomputed_hash == result.recorded_final_hash
                and recomputed_count == result.recorded_frame_count
            )
            if not result.chain_ok:
                result.add_failure(
                    "Frame hash chain mismatch. The video content does not match "
                    "the evidence recorded at capture time -- frames may have been "
                    "added, removed, reordered, or modified."
                )
        except Exception as exc:
            result.add_failure(f"Frame hash chain recomputation error: {exc}")

        # ------------------------------------------------------------
        # Step 4c (optional): Merkle-based tamper localization + perceptual
        # transcode-tolerance fallback (see config.py's "Frame-level
        # tamper localization & perceptual hashing" section). Only runs
        # for recordings made with this feature (has_merkle_data); older
        # recordings verify exactly as before with no change in behavior.
        # Never affects overall_integrity_ok -- it exists purely to make a
        # chain_ok=False result more informative, not to override it.
        # ------------------------------------------------------------
        if full_chain is not None and has_merkle_data:
            result.merkle_checked = True
            try:
                result.merkle_ok = full_chain["merkle_root_hex"] == recorded_chain_info["merkle_root"]

                if not result.merkle_ok:
                    recorded_leaf_blob = base64.b64decode(recorded_chain_info["frame_leaf_hashes_b64"])
                    recorded_leaves = [
                        recorded_leaf_blob[i : i + 32] for i in range(0, len(recorded_leaf_blob), 32)
                    ]
                    recomputed_leaves = full_chain["frame_leaf_hashes"]

                    tampered = [
                        i
                        for i in range(min(len(recorded_leaves), len(recomputed_leaves)))
                        if recorded_leaves[i] != recomputed_leaves[i]
                    ]
                    if len(recorded_leaves) != len(recomputed_leaves):
                        tampered.extend(
                            range(min(len(recorded_leaves), len(recomputed_leaves)), max(len(recorded_leaves), len(recomputed_leaves)))
                        )

                    MAX_REPORTED_FRAMES = 25
                    result.tampered_frame_indices_truncated = len(tampered) > MAX_REPORTED_FRAMES
                    result.tampered_frame_indices = tampered[:MAX_REPORTED_FRAMES]

                    # Perceptual fallback: classify EACH differing frame
                    # individually as "just consistent with ordinary
                    # re-encoding" vs. "content genuinely changed", rather
                    # than judging the whole set with one verdict -- a
                    # realistic case can be a mix of both (most frames just
                    # recompressed, one frame actually altered).
                    if has_perceptual_data and full_chain["perceptual_hashes"] is not None:
                        result.perceptual_hashing_available = True
                        psize = config.PERCEPTUAL_HASH_SIZE_BYTES
                        recorded_p_blob = base64.b64decode(recorded_chain_info["perceptual_hashes_b64"])
                        recorded_phashes = [
                            recorded_p_blob[i : i + psize] for i in range(0, len(recorded_p_blob), psize)
                        ]
                        recomputed_phashes = full_chain["perceptual_hashes"]

                        for i in tampered[:MAX_REPORTED_FRAMES]:
                            if i >= len(recorded_phashes) or i >= len(recomputed_phashes):
                                result.content_altered_frame_indices.append(i)
                                continue
                            distance = hamming_distance_bytes(recorded_phashes[i], recomputed_phashes[i])
                            if distance <= config.PERCEPTUAL_SIMILARITY_THRESHOLD_BITS:
                                result.transcoded_frame_indices.append(i)
                            else:
                                result.content_altered_frame_indices.append(i)
                    else:
                        result.perceptual_hashing_available = False
                        result.content_altered_frame_indices = list(tampered[:MAX_REPORTED_FRAMES])

                    frame_list_str = ", ".join(str(i) for i in result.tampered_frame_indices)
                    if result.tampered_frame_indices_truncated:
                        frame_list_str += ", ... (truncated)"

                    if result.perceptual_hashing_available:
                        result.add_failure(
                            f"Merkle commitment mismatch on {len(tampered)} frame(s) [{frame_list_str}]. "
                            f"Of those, {len(result.transcoded_frame_indices)} look consistent with ordinary "
                            f"lossy re-encoding/recompression, and {len(result.content_altered_frame_indices)} "
                            "show a visual content change beyond what recompression alone would cause. "
                            "This classification is a corroborating signal, not proof -- treat with "
                            "appropriate caution."
                        )
                    else:
                        result.add_failure(
                            f"Merkle commitment mismatch on {len(tampered)} specific frame(s): [{frame_list_str}]"
                        )
            except Exception as exc:
                result.merkle_ok = False
                result.add_failure(f"Merkle tamper-localization check error: {exc}")

        # ------------------------------------------------------------
        # Step 4b (optional): verify the RFC 3161 trusted timestamp, if the
        # recording included one (see crypto_core.py's "RFC 3161 trusted
        # timestamping" section and project_UI.py's stop_recording). This
        # corroborates that the recorded final_hash existed no later than
        # an independent TSA's clock -- not just this machine's local
        # clock -- at capture time. Never affects overall_integrity_ok:
        # recordings made without network access, or before this feature
        # existed, still verify exactly as before.
        # ------------------------------------------------------------
        timestamp_info = payload.get("rfc3161_timestamp")
        if timestamp_info:
            result.timestamp_checked = True
            result.tsa_url = timestamp_info.get("tsa_url")
            try:
                if not result.recorded_final_hash:
                    raise TimestampError("No recorded final hash available to check the timestamp against.")

                token_bytes = base64.b64decode(timestamp_info["token_b64"])
                hash_bytes = bytes.fromhex(result.recorded_final_hash)

                is_valid, tsa_time, error = verify_trusted_timestamp(hash_bytes, token_bytes)
                result.timestamp_ok = is_valid
                result.tsa_timestamp_utc = tsa_time.isoformat() if tsa_time else None
                if not is_valid:
                    result.add_failure(f"RFC 3161 timestamp verification failed: {error}")
            except Exception as exc:
                result.timestamp_ok = False
                result.add_failure(f"RFC 3161 timestamp check error: {exc}")

        # ------------------------------------------------------------
        # Step 5 (optional): cross-check the LSB steganographic reference
        # frame, if the caller supplied one. This is a bonus, independent
        # confirmation that the recorded hash + signature match what was
        # hidden in a genuine pixel-domain (LSB) reference at record time
        # -- immune to the lossy video codec, since the reference is its
        # own lossless PNG (see evidence_storage.py). Never affects
        # overall_integrity_ok; a video verifies exactly as before if no
        # reference frame is supplied.
        # ------------------------------------------------------------
        if stego_reference_path:
            result.lsb_reference_checked = True
            try:
                import cv2

                reference_frame = cv2.imread(stego_reference_path)
                if reference_frame is None:
                    raise EvidenceStorageError(
                        f"Could not read steganographic reference image: {stego_reference_path}"
                    )

                hidden_evidence_id, hidden_bytes = extract_lsb_reference(reference_frame)
                hidden_hash, hidden_signature = unpack_reference(hidden_bytes)
                result.lsb_reference_evidence_id = hidden_evidence_id.hex()

                hash_matches = (
                    result.recorded_final_hash is not None
                    and hidden_hash.hex() == result.recorded_final_hash
                )
                signature_matches = (
                    signature_hex is not None and hidden_signature.hex() == signature_hex
                )

                result.lsb_reference_ok = hash_matches and signature_matches
                if not result.lsb_reference_ok:
                    result.add_failure(
                        "LSB steganographic reference does not match the recorded "
                        "hash/signature. The reference frame and/or the video's "
                        "embedded evidence may not correspond to each other."
                    )
            except EvidenceStorageError as exc:
                result.lsb_reference_ok = False
                result.add_failure(f"LSB reference check failed: {exc}")
            except Exception as exc:
                result.lsb_reference_ok = False
                result.add_failure(f"LSB reference check error: {exc}")

        return result

    @staticmethod
    def _recompute_chain(video_path: str):
        """Re-read every frame of the video and recompute the chained hash."""
        return compute_chain_from_video(video_path)

    @staticmethod
    def _reconstruct_from_chunks(chunk_paths: list, result: "VerificationResult") -> bytes:
        """
        Read whichever chunk reference PNGs are actually valid, and use
        Reed-Solomon erasure decoding to reconstruct the full encrypted
        evidence blob from them. Frames that are missing, unreadable, or
        fail their own checksum are simply skipped -- that's exactly the
        resilience this mechanism exists to provide, not an error by
        itself, as long as enough OTHER chunks are still good.

        Each chunk record now carries its own recording's evidence_id
        (see evidence_storage.py's discover_evidence_pngs()). If
        `chunk_paths` accidentally mixes in chunks belonging to a
        DIFFERENT recording (e.g. a shared stego_refs folder holding
        several recordings' PNGs), those are grouped separately and
        excluded here rather than silently corrupting reconstruction --
        this method uses only the chunks from whichever evidence_id has
        the most valid chunks available.

        Populates result.chunk_recovery_chunks_used/available as a
        side effect, for display in the GUI/report.
        """
        import cv2
        from collections import defaultdict

        # evidence_id_hex -> {"available": {chunk_index: bytes}, "num_data_chunks": int, "num_parity_chunks": int}
        groups = defaultdict(lambda: {"available": {}, "num_data_chunks": None, "num_parity_chunks": None})

        for path in chunk_paths:
            frame = cv2.imread(path)
            if frame is None:
                continue
            try:
                evidence_id, chunk_index, total_chunks, data_count, chunk_bytes = extract_chunk_from_frame(frame)
            except (ChunkNotFoundError, ChunkCorruptedError):
                continue  # skip this one; other chunks may still be enough

            group = groups[evidence_id.hex()]
            group["num_data_chunks"] = data_count
            group["num_parity_chunks"] = total_chunks - data_count
            group["available"][chunk_index] = chunk_bytes

        if not groups:
            result.chunk_recovery_chunks_available = 0
            raise EvidenceStorageError("None of the supplied reference frames contained a valid chunk.")

        # If multiple recordings' chunks ended up mixed together, use
        # whichever evidence_id has the most chunks available -- almost
        # always the correct one, since a folder normally only holds
        # chunks belonging to the video actually being verified.
        best_evidence_id, best_group = max(groups.items(), key=lambda kv: len(kv[1]["available"]))
        result.chunk_recovery_chunks_available = len(best_group["available"])
        result.chunk_recovery_evidence_id = best_evidence_id

        num_data_chunks = best_group["num_data_chunks"]
        num_parity_chunks = best_group["num_parity_chunks"]

        reconstructed = erasure_decode(best_group["available"], num_data_chunks, num_parity_chunks)
        result.chunk_recovery_chunks_used = min(len(best_group["available"]), num_data_chunks)
        return reconstructed
