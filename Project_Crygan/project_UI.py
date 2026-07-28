"""
project_UI.py
---------------
Merged module for Project Crygan containing every GUI screen plus all
of their non-cryptographic supporting logic, combined unchanged from:

    * theme.py          -- light/dark theming
    * database.py       -- SQLite evidence index
    * remember.py       -- optional "remember my password" convenience
    * location.py       -- GPS / IP geolocation resolution
    * recorder.py       -- webcam capture + evidence pipeline orchestration
    * app_state.py      -- session-scoped shared state
    * report.py         -- PDF evidence report generation
    * main_window.py    -- top-level window / sidebar navigation
    * record_view.py    -- "Record Video" screen
    * reports_view.py   -- "Evidence Reports" screen
    * settings_view.py  -- "Settings" screen
    * verify_view.py    -- "Verify Video" screen

Cryptographic primitives, key management, hashing, and verification
live in crypto_core.py; steganographic embedding/extraction lives in
evidence_storage.py; shared constants/paths live in config.py. This
module imports from all three (one direction only -- none of them
import from project_UI.py), so there is no circular dependency.

THREADING NOTE: recording a video's evidence pipeline
(VideoRecorder.stop_recording) and verifying one
(VerificationEngine.verify) both decode and hash every single frame
of the video file. Doing that on the GUI thread would freeze the
window ("Not Responding") for any recording longer than a few
seconds. Both RecordView and VerifyView instead run that work on a
background QThread (see `_BackgroundTask` below, a small addition
that did not exist as a separate file before) and only touch widgets
again once a `succeeded`/`failed` Qt signal delivers the result back
on the main thread.
"""

import base64
import datetime
import logging
import os
import sqlite3
import stat
import time
import uuid

import cv2
import requests
from cryptography.fernet import Fernet

from PySide6.QtCore import QObject, Signal, QSettings, Qt, QThread, QTimer, QUrl
from PySide6.QtGui import QPalette, QFont, QImage, QPixmap, QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QWidget,
    QMainWindow,
    QHBoxLayout,
    QVBoxLayout,
    QPushButton,
    QStackedWidget,
    QLabel,
    QFrame,
    QComboBox,
    QMessageBox,
    QLineEdit,
    QFileDialog,
    QButtonGroup,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QTextEdit,
    QInputDialog,
)

from reportlab.lib.pagesizes import LETTER
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

import config
from crypto_core import (
    KeyManager,
    KeyManagerError,
    VerificationEngine,
    HashChain,
    compute_full_chain_from_video,
    encrypt_json,
    request_trusted_timestamp,
    TimestampError,
    sample_fingerprint,
)
from evidence_storage import (
    embed_payload,
    write_companion_file,
    companion_file_path_for,
    pack_reference,
    embed_lsb_reference,
    erasure_encode,
    embed_chunk_into_frame,
    pick_evenly_spaced_frame_indices,
    discover_evidence_pngs,
    export_evidence_bundle,
    EvidenceStorageError,
)
import glob

# ==========================================================================
# Threading utility (new -- not from any single original file)
# ==========================================================================
class _BackgroundTask(QThread):
    """
    Runs a single callable on a background thread and reports the outcome
    back to the GUI thread via Qt signals.

    Used to keep the main/GUI thread responsive during the two
    operations in this app that decode and hash every frame of a video
    (VideoRecorder.stop_recording and VerificationEngine.verify) --
    running those synchronously on the GUI thread would otherwise freeze
    the window for the duration of the hashing loop on anything but a
    very short clip.

    Usage:
        worker = _BackgroundTask(some_callable, arg1, kwarg=value)
        worker.succeeded.connect(on_success)   # receives the return value
        worker.failed.connect(on_failure)      # receives str(exception)
        worker.start()

    IMPORTANT: callers must keep a reference to the worker (e.g.
    `self._worker = _BackgroundTask(...)`) for as long as it may be
    running, or Python may garbage-collect it out from under the
    running QThread.
    """

    succeeded = Signal(object)
    failed = Signal(str)

    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self._func = func
        self._args = args
        self._kwargs = kwargs

    def run(self):
        try:
            result = self._func(*self._args, **self._kwargs)
        except Exception as exc:  # noqa: BLE001 -- deliberately broad: any
            # failure in the wrapped call must reach the GUI thread as a
            # message rather than crashing the worker thread silently.
            self.failed.emit(str(exc))
        else:
            self.succeeded.emit(result)

# ==========================================================================
# Originally: theme.py
# ==========================================================================
"""
theme.py
--------
Centralized light/dark theming for Project Crygan.

Provides:
    * ThemeManager -- a QObject that tracks the current theme mode
      ("system", "light", "dark"), resolves "system" against the OS's
      current color scheme, persists the user's manual choice across
      restarts, and emits a Qt signal whenever the effective theme
      changes so every open view updates live (no restart required).
    * build_stylesheet(dark) -- builds a single global Qt stylesheet
      (QSS) from a small palette of semantic color tokens, applied once
      to the whole QApplication. Individual widgets opt into styled
      roles via a `class` dynamic property (see set_class()) rather than
      hard-coding colors themselves, so every widget in the app reacts
      to theme changes uniformly from this one place.

Usage:
    theme_manager = ThemeManager(app)               # in main.py
    theme_manager.theme_changed.connect(callback)    # optional, per-view
    theme_manager.set_mode("dark")                   # "light" / "system"
"""



LIGHT = "light"
DARK = "dark"
SYSTEM = "system"
VALID_MODES = (SYSTEM, LIGHT, DARK)

_SETTINGS_KEY = "appearance/theme_mode"

LIGHT_COLORS = {
    "bg": "#f5f6f8",
    "surface": "#ffffff",
    "surface_alt": "#f0f2f5",
    "border": "#e2e5ea",
    "text": "#1b1f2a",
    "subtext": "#5a6270",
    "muted": "#7f8798",
    "accent": "#2f80ed",
    "accent_hover": "#2566c4",
    "accent_disabled": "#b9c4d6",
    "sidebar_bg": "#1b1f2a",
    "sidebar_text": "#d7dae0",
    "sidebar_hover": "#262c3a",
    "success": "#1a7f37",
    "danger": "#c62828",
    "input_bg": "#ffffff",
    "preview_bg": "#10131a",
}

DARK_COLORS = {
    "bg": "#14161d",
    "surface": "#1c1f29",
    "surface_alt": "#20232e",
    "border": "#2e323f",
    "text": "#e7e9ee",
    "subtext": "#a7adba",
    "muted": "#7f8798",
    "accent": "#4c92f0",
    "accent_hover": "#3d7cd6",
    "accent_disabled": "#3a4152",
    "sidebar_bg": "#0d0f14",
    "sidebar_text": "#c7ccd6",
    "sidebar_hover": "#1c2029",
    "success": "#3fb950",
    "danger": "#f0605c",
    "input_bg": "#20232e",
    "preview_bg": "#000000",
}


def set_class(widget: QWidget, class_name: str):
    """
    Tag a widget with a semantic style class consumed by the QSS built in
    build_stylesheet(). Keeping styling declarative (via this property)
    rather than ad-hoc per-widget setStyleSheet() calls is what allows a
    single theme switch to re-color the entire application at once.
    """
    widget.setProperty("class", class_name)


class ThemeManager(QObject):
    """Owns the current theme mode and applies the resulting stylesheet."""

    theme_changed = Signal(bool)  # emits is_dark whenever the effective theme changes

    def __init__(self, app: QApplication):
        super().__init__()
        self._app = app
        self._settings = QSettings(config.ORGANIZATION_NAME, config.APP_NAME)

        stored_mode = self._settings.value(_SETTINGS_KEY, SYSTEM)
        self._mode = stored_mode if stored_mode in VALID_MODES else SYSTEM

        # Follow OS theme changes live while in "system" mode (Qt 6.5+).
        style_hints = getattr(self._app, "styleHints", lambda: None)()
        if style_hints is not None and hasattr(style_hints, "colorSchemeChanged"):
            style_hints.colorSchemeChanged.connect(self._on_system_scheme_changed)

        self.apply()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    @property
    def mode(self) -> str:
        """Current mode setting: 'system', 'light', or 'dark'."""
        return self._mode

    def is_dark(self) -> bool:
        """Whether the currently *effective* theme is dark."""
        return self._resolve_dark()

    def set_mode(self, mode: str):
        """Change the theme mode and immediately re-apply the stylesheet."""
        if mode not in VALID_MODES:
            raise ValueError(f"Invalid theme mode: {mode!r}")
        self._mode = mode
        self._settings.setValue(_SETTINGS_KEY, mode)
        self.apply()

    def apply(self):
        """(Re)build and install the global stylesheet for the current mode."""
        dark = self._resolve_dark()
        self._app.setStyleSheet(build_stylesheet(dark))
        self.theme_changed.emit(dark)

    def colors(self) -> dict:
        """The active color token dict, for any view that needs raw values."""
        return DARK_COLORS if self._resolve_dark() else LIGHT_COLORS

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _resolve_dark(self) -> bool:
        if self._mode == DARK:
            return True
        if self._mode == LIGHT:
            return False
        return self._detect_system_dark()

    def _detect_system_dark(self) -> bool:
        style_hints = getattr(self._app, "styleHints", lambda: None)()
        if style_hints is not None and hasattr(style_hints, "colorScheme"):
            try:
                return style_hints.colorScheme() == Qt.ColorScheme.Dark
            except Exception:
                pass
        # Fallback for platforms/Qt builds without colorScheme(): infer
        # from the default palette's window background luminance.
        color = self._app.palette().color(QPalette.Window)
        luminance = 0.299 * color.red() + 0.587 * color.green() + 0.114 * color.blue()
        return luminance < 128

    def _on_system_scheme_changed(self, *_args):
        if self._mode == SYSTEM:
            self.apply()


def build_stylesheet(dark: bool) -> str:
    """Build the full application QSS for the given dark/light state."""
    c = DARK_COLORS if dark else LIGHT_COLORS
    return f"""
    QMainWindow, QWidget {{
        background-color: {c['bg']};
        color: {c['text']};
        font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
    }}

    QFrame[class="sidebar"] {{
        background-color: {c['sidebar_bg']};
    }}
    QFrame[class="sidebar"] QLabel {{ background-color: transparent; }}
    QFrame[class="sidebar"] QPushButton {{
        color: {c['sidebar_text']};
        background-color: transparent;
        border: none;
        text-align: left;
        padding: 14px 22px;
        font-size: 14px;
    }}
    QFrame[class="sidebar"] QPushButton:hover {{
        background-color: {c['sidebar_hover']};
    }}
    QFrame[class="sidebar"] QPushButton:checked {{
        background-color: {c['accent']};
        color: white;
        font-weight: 600;
    }}
    QLabel[class="sidebar-title"] {{ color: white; }}
    QLabel[class="sidebar-version"] {{ color: {c['muted']}; font-size: 11px; }}

    QStackedWidget {{ background-color: {c['bg']}; }}

    QFrame[class="card"] {{
        background-color: {c['surface']};
        border-radius: 8px;
        border: 1px solid {c['border']};
    }}
    QFrame[class="preview"] {{
        background-color: {c['preview_bg']};
        border-radius: 8px;
    }}
    QFrame[class="preview"] QLabel {{ background-color: transparent; }}

    QLabel[class="heading"] {{ font-size: 22px; font-weight: 700; color: {c['text']}; }}
    QLabel[class="subheading"] {{ color: {c['subtext']}; font-size: 13px; }}
    QLabel[class="section-title"] {{ font-size: 15px; font-weight: 700; color: {c['text']}; }}
    QLabel[class="muted"] {{ color: {c['subtext']}; font-size: 12px; }}
    QLabel[class="status"] {{ color: {c['text']}; font-size: 13px; font-weight: 600; }}
    QLabel[class="preview-placeholder"] {{ color: {c['muted']}; font-size: 13px; }}

    QPushButton[class="primary"] {{
        background-color: {c['accent']};
        color: white;
        border: none;
        border-radius: 6px;
        padding: 0 18px;
        font-size: 13px;
        font-weight: 600;
    }}
    QPushButton[class="primary"]:disabled {{ background-color: {c['accent_disabled']}; }}
    QPushButton[class="primary"]:hover:!disabled {{ background-color: {c['accent_hover']}; }}

    QPushButton[class="secondary"] {{
        background-color: {c['surface_alt']};
        color: {c['text']};
        border: 1px solid {c['border']};
        border-radius: 6px;
        padding: 0 16px;
        font-size: 13px;
        font-weight: 600;
    }}
    QPushButton[class="secondary"]:hover {{ background-color: {c['border']}; }}

    QPushButton[class="segment"] {{
        background-color: {c['surface_alt']};
        color: {c['text']};
        border: 1px solid {c['border']};
        padding: 6px 14px;
        font-size: 12px;
        font-weight: 600;
    }}
    QPushButton[class="segment"]:checked {{
        background-color: {c['accent']};
        color: white;
        border: 1px solid {c['accent']};
    }}
    QPushButton[class="segment"]:hover:!checked {{ background-color: {c['border']}; }}

    QLineEdit, QSpinBox, QTextEdit, QComboBox {{
        background-color: {c['input_bg']};
        color: {c['text']};
        border: 1px solid {c['border']};
        border-radius: 6px;
        padding: 6px 8px;
        selection-background-color: {c['accent']};
    }}
    QComboBox::drop-down {{
        border: none;
        width: 22px;
    }}
    QComboBox QAbstractItemView {{
        background-color: {c['surface']};
        color: {c['text']};
        border: 1px solid {c['border']};
        selection-background-color: {c['accent']};
        selection-color: white;
        outline: none;
    }}

    QTableWidget {{
        background-color: {c['surface']};
        color: {c['text']};
        gridline-color: {c['border']};
        border: 1px solid {c['border']};
        border-radius: 6px;
    }}
    QHeaderView::section {{
        background-color: {c['surface_alt']};
        color: {c['text']};
        padding: 6px;
        border: none;
        border-bottom: 1px solid {c['border']};
        font-weight: 600;
    }}
    QTableWidget::item:selected {{
        background-color: {c['accent']};
        color: white;
    }}

    QMessageBox {{ background-color: {c['surface']}; }}

    QScrollBar:vertical {{ background: transparent; width: 10px; margin: 0; }}
    QScrollBar::handle:vertical {{ background: {c['border']}; border-radius: 5px; min-height: 24px; }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
    """

# ==========================================================================
# Originally: database.py
# ==========================================================================
"""
database.py
-----------
Lightweight SQLite persistence layer for Project Crygan.

Stores an index of evidence records (one per recorded video) so the
"Evidence Reports" screen can list past recordings and their verification
history without needing to re-scan the videos/ and reports/ folders.

This module intentionally exposes a small, explicit API rather than a full
ORM, to keep the MVP simple and dependency-light (sqlite3 is part of the
Python standard library).
"""




def _normalize_path(path: str) -> str:
    """
    Normalize a filesystem path for reliable comparison/storage.

    Video paths can reach this module in different forms -- e.g.
    recorder.py builds them with os.path.join() (native separators),
    while Qt's QFileDialog (used in verify_view.py) tends to return
    paths with forward slashes even on Windows, and either could be
    relative vs. absolute depending on the caller. Without normalizing,
    a video recorded and later re-selected for verification could fail
    an exact-string match here even though it's the same file on disk --
    which previously showed up as "Evidence ID: unknown" in generated
    reports, since the lookup silently returned no matching record.
    """
    return os.path.normcase(os.path.normpath(os.path.abspath(path)))


class EvidenceDatabase:
    """Thin wrapper around a single SQLite database file."""

    def __init__(self, db_path: str = config.DATABASE_PATH):
        self._db_path = db_path
        self._initialize_schema()

    def _connect(self):
        return sqlite3.connect(self._db_path)

    def _initialize_schema(self):
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS evidence_records (
                    evidence_id TEXT PRIMARY KEY,
                    video_filename TEXT NOT NULL,
                    video_path TEXT NOT NULL,
                    recorded_at_utc TEXT NOT NULL,
                    latitude REAL,
                    longitude REAL,
                    frame_count INTEGER,
                    final_hash TEXT,
                    created_at_utc TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS verification_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    evidence_id TEXT,
                    verified_at_utc TEXT NOT NULL,
                    integrity_ok INTEGER,
                    signature_ok INTEGER,
                    chain_ok INTEGER,
                    report_path TEXT
                )
                """
            )
            # Out-of-band evidence recovery registry (see config.py's
            # "Local perceptual-hash evidence registry" section). Holds an
            # independent copy of each recording's encrypted evidence
            # payload plus a compact perceptual fingerprint, so a video
            # that's been transcoded/re-encoded after recording -- which
            # strips anything embedded in the file itself, no matter how
            # it was embedded -- can still be recognized by content and
            # matched back to its original signed evidence.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS local_evidence_registry (
                    evidence_id TEXT PRIMARY KEY,
                    recorded_at_utc TEXT NOT NULL,
                    frame_count INTEGER,
                    final_hash TEXT,
                    merkle_root TEXT,
                    fingerprint_b64 TEXT,
                    encrypted_payload_b64 TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL
                )
                """
            )
            conn.commit()

    # ------------------------------------------------------------------
    # Evidence records
    # ------------------------------------------------------------------
    def create_evidence_record(
        self,
        video_filename: str,
        video_path: str,
        recorded_at_utc: str,
        latitude: float,
        longitude: float,
        frame_count: int,
        final_hash: str,
    ) -> str:
        """Insert a new evidence record and return its generated evidence ID."""
        evidence_id = str(uuid.uuid4())
        created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO evidence_records
                (evidence_id, video_filename, video_path, recorded_at_utc,
                 latitude, longitude, frame_count, final_hash, created_at_utc)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evidence_id,
                    video_filename,
                    _normalize_path(video_path),
                    recorded_at_utc,
                    latitude,
                    longitude,
                    frame_count,
                    final_hash,
                    created_at,
                ),
            )
            conn.commit()

        return evidence_id

    def list_evidence_records(self):
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM evidence_records ORDER BY created_at_utc DESC"
            ).fetchall()
            return [dict(row) for row in rows]

    def get_evidence_record_by_video_path(self, video_path: str):
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM evidence_records WHERE video_path = ?",
                (_normalize_path(video_path),),
            ).fetchone()
            return dict(row) if row else None

    # ------------------------------------------------------------------
    # Local out-of-band evidence registry (see config.py's "Local
    # perceptual-hash evidence registry" section)
    # ------------------------------------------------------------------
    def add_registry_entry(
        self,
        evidence_id: str,
        recorded_at_utc: str,
        frame_count: int,
        final_hash: str,
        merkle_root: str,
        fingerprint_b64: str,
        encrypted_payload_b64: str,
    ):
        """
        Store an independent copy of this recording's encrypted evidence
        payload plus its perceptual fingerprint, so verification can
        still recover it later even if a transcoded/re-encoded copy of
        the video has nothing usable embedded in it at all.
        """
        created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO local_evidence_registry
                (evidence_id, recorded_at_utc, frame_count, final_hash,
                 merkle_root, fingerprint_b64, encrypted_payload_b64, created_at_utc)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evidence_id,
                    recorded_at_utc,
                    frame_count,
                    final_hash,
                    merkle_root,
                    fingerprint_b64,
                    encrypted_payload_b64,
                    created_at,
                ),
            )
            conn.commit()

    def list_registry_entries(self):
        """
        Return all locally-registered evidence entries as a list of dicts
        with keys evidence_id/fingerprint_b64/encrypted_payload_b64 (among
        others) -- ready to pass straight into
        VerificationEngine.verify(registry_candidates=...).
        """
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM local_evidence_registry").fetchall()
            return [dict(row) for row in rows]

    def delete_evidence_record(self, evidence_id: str):
        """Delete a single evidence record and its verification history.

        Note: this only removes the database entry, not the underlying
        video file on disk.
        """
        with self._connect() as conn:
            conn.execute(
                "DELETE FROM verification_history WHERE evidence_id = ?", (evidence_id,)
            )
            conn.execute(
                "DELETE FROM evidence_records WHERE evidence_id = ?", (evidence_id,)
            )
            conn.commit()

    def delete_all_evidence_records(self):
        """Delete every evidence record and all verification history.

        Note: this only clears the database; it does not touch any video
        files on disk.
        """
        with self._connect() as conn:
            conn.execute("DELETE FROM verification_history")
            conn.execute("DELETE FROM evidence_records")
            conn.commit()

    # ------------------------------------------------------------------
    # Verification history
    # ------------------------------------------------------------------
    def record_verification(
        self,
        evidence_id: str,
        integrity_ok: bool,
        signature_ok: bool,
        chain_ok: bool,
        report_path: str,
    ):
        verified_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO verification_history
                (evidence_id, verified_at_utc, integrity_ok, signature_ok, chain_ok, report_path)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    evidence_id,
                    verified_at,
                    int(integrity_ok),
                    int(signature_ok),
                    int(chain_ok),
                    report_path,
                ),
            )
            conn.commit()

    def list_verification_history(self, evidence_id: str = None):
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            if evidence_id:
                rows = conn.execute(
                    "SELECT * FROM verification_history WHERE evidence_id = ? "
                    "ORDER BY verified_at_utc DESC",
                    (evidence_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM verification_history ORDER BY verified_at_utc DESC"
                ).fetchall()
            return [dict(row) for row in rows]

# ==========================================================================
# Originally: remember.py
# ==========================================================================
"""
remember.py
-----------
Optional "remember my password" convenience feature.

Without this, the user has to retype their key/evidence session password
every single time the app is launched, even though the same password was
already used successfully last time -- Settings never asked to unlock
again "for real", it just forgot. This module lets AppState silently
re-apply the last-known-good password on startup so Check Location (and
everything else that needs the key manager) just works, the same way it
did at the end of the previous session.

IMPORTANT SECURITY NOTE:
This trades a little security for convenience, and is meant to be used
that way deliberately -- like a browser's "remember me". The password is
NOT stored in plaintext: it's encrypted with a locally generated Fernet
key (`config.REMEMBER_LOCAL_KEY_PATH`). But that key is stored right next
to the encrypted password (`config.REMEMBER_PASSWORD_PATH`), both
best-effort restricted to the current OS user account -- there is no
secret (like a second password) gating access the way there is for the
actual private key in keys.py. Anyone with access to this machine/user
account could, in principle, recover the remembered password. Users
recording sensitive evidence on a shared or untrusted machine should use
"Forget Saved Password" in Settings instead of relying on this feature.
"""





def save_password(password: str):
    """Encrypt and persist `password` so it can be silently restored later."""
    key = _get_or_create_local_key()
    token = Fernet(key).encrypt(password.encode("utf-8"))
    with open(config.REMEMBER_PASSWORD_PATH, "wb") as f:
        f.write(token)
    _restrict_permissions(config.REMEMBER_PASSWORD_PATH)


def load_password():
    """
    Return the previously remembered password, or None if none is saved
    (or it can't be decrypted, e.g. after "Forget Saved Password").
    Never raises.
    """
    if not (
        os.path.exists(config.REMEMBER_LOCAL_KEY_PATH)
        and os.path.exists(config.REMEMBER_PASSWORD_PATH)
    ):
        return None

    try:
        key = _get_or_create_local_key()
        with open(config.REMEMBER_PASSWORD_PATH, "rb") as f:
            token = f.read()
        return Fernet(key).decrypt(token).decode("utf-8")
    except Exception:
        return None


def clear_password():
    """Forget any saved password. Leaves the actual key files untouched."""
    for path in (config.REMEMBER_PASSWORD_PATH, config.REMEMBER_LOCAL_KEY_PATH):
        try:
            os.remove(path)
        except OSError:
            pass


def _get_or_create_local_key() -> bytes:
    if os.path.exists(config.REMEMBER_LOCAL_KEY_PATH):
        with open(config.REMEMBER_LOCAL_KEY_PATH, "rb") as f:
            return f.read()

    key = Fernet.generate_key()
    with open(config.REMEMBER_LOCAL_KEY_PATH, "wb") as f:
        f.write(key)
    _restrict_permissions(config.REMEMBER_LOCAL_KEY_PATH)
    return key


def _restrict_permissions(path: str):
    """Best-effort restriction of file permissions to the current user."""
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        # Not all platforms (e.g. Windows) support POSIX chmod bits.
        pass

# ==========================================================================
# Originally: location.py
# ==========================================================================
"""
location.py
------------
Location resolution for Project Crygan.

Most desktop and laptop computers do not have dedicated GPS hardware, so
this module resolves an approximate location using IP-based geolocation.
The architecture is intentionally abstracted behind `get_current_location`
so a future version can plug in a real GPS receiver (e.g. via a serial
NMEA feed) without changing any calling code in recorder.py.

Per the project specification, recording MUST NOT proceed unless a valid
location is obtained.
"""




logger = logging.getLogger(__name__)


class LocationError(Exception):
    """Raised when location cannot be determined."""


class LocationResult:
    """Simple data holder for a resolved location."""

    def __init__(
        self,
        latitude: float,
        longitude: float,
        source: str,
        city: str = "",
        country: str = "",
        accuracy_meters: float = None,
    ):
        self.latitude = latitude
        self.longitude = longitude
        self.source = source
        self.city = city
        self.country = country
        self.accuracy_meters = accuracy_meters
        self.resolved_at_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "latitude": self.latitude,
            "longitude": self.longitude,
            "source": self.source,
            "city": self.city,
            "country": self.country,
            "accuracy_meters": self.accuracy_meters,
            "resolved_at_utc": self.resolved_at_utc,
        }


def build_maps_url(latitude: float, longitude: float) -> str:
    """
    Build a URL that opens the given coordinates in Google Maps (any
    installed maps app that handles this URL scheme, or the default
    browser as a fallback). Used by the "Open in Maps" buttons in the
    GUI so the user can visually confirm where a location actually
    resolved to.
    """
    return f"https://www.google.com/maps/search/?api=1&query={latitude},{longitude}"


def _reverse_geocode_city_country(latitude: float, longitude: float):
    """
    Resolve a human-readable city/country for a raw coordinate pair via
    reverse geocoding (OpenStreetMap Nominatim).

    This exists because precise coordinate sources -- Windows Location
    Services in particular -- only ever return a lat/lon, unlike
    IP-based geolocation, whose provider already returns a city/country
    alongside the coordinates as part of the same lookup. Without this,
    a Windows-Location-Services result would show blank/"unknown" city
    and country everywhere in the UI even though the coordinates
    themselves are accurate.

    Best-effort: returns ("", "") on any failure (no network, rate
    limited, unexpected response shape, etc.) so a reverse-geocoding
    hiccup never blocks recording -- only the lat/lon are actually
    required for evidence to be valid.
    """
    try:
        response = requests.get(
            "https://nominatim.openstreetmap.org/reverse",
            params={
                "format": "jsonv2",
                "lat": latitude,
                "lon": longitude,
                "zoom": 10,
                "addressdetails": 1,
            },
            headers={"User-Agent": f"{config.APP_NAME}/{config.APP_VERSION}"},
            timeout=config.LOCATION_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        address = response.json().get("address", {})

        city = (
            address.get("city")
            or address.get("town")
            or address.get("village")
            or address.get("municipality")
            or address.get("county")
            or ""
        )
        country = address.get("country", "")
        return city, country
    except Exception as exc:
        logger.warning(
            "Reverse geocoding failed for (%s, %s): %s. City/country will "
            "be shown as unknown; the coordinates themselves are unaffected.",
            latitude,
            longitude,
            exc,
        )
        return "", ""


def get_current_location() -> LocationResult:
    """
    Attempt to resolve the current location, most-precise method first.

    Order of preference:
        1. OS-level location services (Windows Location API), which use
           GPS / WiFi-positioning / cell data under the hood and are
           typically accurate to tens of meters -- a real coordinate, not
           just "which city are you near".
        2. IP-based geolocation (ip-api.com) as a universal fallback. This
           method is inherently approximate: it resolves to your ISP's
           network routing point, which is often accurate only to
           city/metro level (sometimes several km off), regardless of the
           lat/lon decimal precision the API returns.

    Raises:
        LocationError: if no location could be determined by any available
            method. Callers (the recording workflow) must treat this as a
            hard stop and refuse to begin recording.
    """
    result = _get_windows_location()
    if result is not None:
        return result

    try:
        response = requests.get(config.IP_GEOLOCATION_URL, timeout=config.LOCATION_TIMEOUT_SECONDS)
        response.raise_for_status()
        data = response.json()

        if data.get("status") != "success":
            raise LocationError("Location provider could not resolve a location for this network.")

        return LocationResult(
            latitude=float(data["lat"]),
            longitude=float(data["lon"]),
            source="ip-geolocation (approximate, city-level)",
            city=data.get("city", ""),
            country=data.get("country", ""),
            accuracy_meters=None,  # ip-api does not report an accuracy radius
        )
    except LocationError:
        raise
    except Exception as exc:
        raise LocationError(
            "Location access is required to record evidence. "
            "Please enable location services / network access and try again."
        ) from exc


def _get_windows_location():
    """
    Try to resolve a high-precision location via the Windows Location API
    (uses GPS/WiFi/cell positioning, same system used by Maps, Weather,
    etc.). Returns None (never raises) if unavailable, denied, or not on
    Windows, so get_current_location() can transparently fall back to IP
    geolocation.

    Requires the optional `winsdk` package:
        pip install winsdk
    and the user granting Location permission to desktop apps in
    Windows Settings > Privacy & security > Location.
    """
    import sys

    if sys.platform != "win32":
        return None

    try:
        import asyncio
        from winsdk.windows.devices.geolocation import Geolocator, PositionAccuracy

        async def _resolve():
            locator = Geolocator()
            locator.desired_accuracy = PositionAccuracy.HIGH
            position = await locator.get_geoposition_async()
            coord = position.coordinate
            return coord

        coord = asyncio.run(_resolve())
        point = coord.point.position  # BasicGeoposition: latitude/longitude/altitude

        # winsdk only ever gives us raw coordinates -- resolve city/country
        # separately so the rest of the app (status text, verification
        # results, PDF reports) doesn't show blank/"unknown" place names
        # just because the precise source doesn't include them itself.
        city, country = _reverse_geocode_city_country(point.latitude, point.longitude)

        return LocationResult(
            latitude=float(point.latitude),
            longitude=float(point.longitude),
            source="windows-location-services",
            city=city,
            country=country,
            accuracy_meters=float(coord.accuracy) if coord.accuracy else None,
        )
    except ImportError:
        # winsdk not installed -- silently fall back to IP geolocation.
        logger.info(
            "winsdk is not installed, so precise Windows location services "
            "can't be used. Falling back to approximate IP geolocation. "
            "Install it with: pip install winsdk"
        )
        return None
    except Exception as exc:
        # Permission denied, no sensors available, timed out, etc. --
        # fall back to IP-based location rather than hard-failing, since
        # IP-based location is still a valid (if coarser) source. Logging
        # the real reason here (rather than staying silent) is what makes
        # it possible to tell "permission not granted" apart from "no
        # network" apart from "timed out", instead of every failure just
        # quietly becoming a city-level IP lookup with no explanation.
        logger.warning(
            "Windows location services unavailable (%s: %s). Falling back "
            "to approximate IP geolocation. Check Windows Settings > "
            "Privacy & security > Location, and ensure both the system-wide "
            "toggle and per-app access for desktop apps are turned on.",
            type(exc).__name__,
            exc,
        )
        return None

# ==========================================================================
# Originally: recorder.py
# ==========================================================================
"""
recorder.py
-----------
Handles webcam capture and orchestrates the evidence-generation pipeline:

    1. Resolve location (mandatory; aborts recording if unavailable).
    2. Capture precise start timestamp.
    3. Stream frames from the webcam via OpenCV, writing them to a video
       file while simultaneously feeding each frame into a chained
       SHA-256 hash (hash_chain.py).
    4. On stop, assemble the evidence package (GPS, timestamp, hash chain,
       camera info), sign it with the ECC private key (keys.py), encrypt
       it with AES-256 (crypto_utils.py), and embed it into the video file
       (evidence_storage.py).
    5. Persist a record of the evidence in the local database.

This module is UI-agnostic: the GUI (record_view.py) drives it through a
small, explicit state machine (idle -> location_check -> recording -> saved).
"""





class RecorderError(Exception):
    """Raised for any unrecoverable recording failure."""


class VideoRecorder:
    """Manages a single webcam recording session and its evidence pipeline."""

    def __init__(self, key_manager, camera_index: int = config.DEFAULT_CAMERA_INDEX):
        self._key_manager = key_manager
        self._camera_index = camera_index

        self._capture = None
        self._active_camera_index = None
        self._writer = None
        self._hash_chain = HashChain()
        self._db = EvidenceDatabase()

        self._is_recording = False
        self._output_path = None
        self._location_result = None
        self._start_time_utc = None
        self._start_time_local = None

    # ------------------------------------------------------------------
    # Public state
    # ------------------------------------------------------------------
    @property
    def is_recording(self) -> bool:
        return self._is_recording

    @property
    def active_camera_index(self):
        """The camera index actually in use for the open preview/recording, or None."""
        return self._active_camera_index

    @staticmethod
    def list_available_cameras(max_index: int = 6) -> list:
        """
        Probe camera indices 0..max_index-1 and return the ones that can
        actually be opened right now. Used both to populate the camera
        picker in Settings and to find a working fallback camera if the
        configured index is no longer available (e.g. an external webcam
        was unplugged).
        """
        available = []
        for idx in range(max_index):
            cap = cv2.VideoCapture(idx)
            try:
                if cap is not None and cap.isOpened():
                    available.append(idx)
            finally:
                if cap is not None:
                    cap.release()
        return available

    @staticmethod
    def list_available_cameras_with_names(max_index: int = 6) -> list:
        """
        Like list_available_cameras(), but pairs each index with a human
        -readable device name where possible, e.g. "Iriun Webcam" vs.
        "Integrated Webcam", instead of an opaque index number.

        This matters because virtual-camera apps (Iriun, DroidCam, OBS
        Virtual Camera, etc.) register a device that stays "open" and
        keeps returning a valid frame even after the phone/source
        disconnects -- often a placeholder image telling the user to
        reconnect. That frame is NOT a read failure, so this app has no
        reliable way to automatically detect "the real camera behind this
        index is actually gone" from frame data alone. Naming devices
        clearly lets the user manually pick the right one (e.g. switch
        back to their laptop's built-in camera) with confidence, instead
        of the app guessing wrong.

        On Windows this uses the optional `pygrabber` package to read
        actual DirectShow device names. Install with:
            pip install pygrabber
        Falls back to generic "Camera N" labels if pygrabber isn't
        installed or we're not on Windows.

        Returns:
            List of (index, name) tuples for every camera that opened.
        """
        available = VideoRecorder.list_available_cameras(max_index)

        names_by_index = {}
        try:
            from pygrabber.dshow_graph import FilterGraph

            graph = FilterGraph()
            for idx, name in enumerate(graph.get_input_devices()):
                names_by_index[idx] = name
        except Exception:
            # pygrabber not installed, not on Windows, or DirectShow
            # enumeration failed for some other reason -- fall back to
            # generic labels below rather than erroring out.
            pass

        return [(idx, names_by_index.get(idx, f"Camera {idx}")) for idx in available]

    def set_camera_index(self, camera_index: int):
        """
        Change which camera index this recorder will use going forward.
        Does not affect an already-open preview/recording -- call
        close_preview() and open_camera_for_preview() again (or just let
        the next open_camera_for_preview() call pick it up) to actually
        switch the live feed.
        """
        self._camera_index = camera_index

    # ------------------------------------------------------------------
    # Recording lifecycle
    # ------------------------------------------------------------------
    def check_location_or_raise(self):
        """
        Resolve the current location. Must succeed before recording may
        begin, per Project Crygan's mandatory-location policy.
        """
        self._location_result = get_current_location()  # raises LocationError on failure
        return self._location_result

    # ------------------------------------------------------------------
    # Live preview (before recording starts)
    # ------------------------------------------------------------------
    def open_camera_for_preview(self) -> int:
        """
        Open a camera for a live preview, before any recording begins.
        Tries the configured camera_index first; if that fails (e.g. an
        external webcam was unplugged since Settings was last opened),
        automatically scans other camera indices and falls back to the
        first one that actually works -- instead of hard-failing and
        forcing the user to go back into Settings and manually reconfigure
        the camera index every time they swap devices.

        Returns:
            The camera index that was actually opened.

        Raises:
            RecorderError: if no camera at all could be opened.
        """
        if self._capture is not None and self._capture.isOpened():
            return self._active_camera_index

        candidate_indices = [self._camera_index] + [
            i for i in range(6) if i != self._camera_index
        ]

        for idx in candidate_indices:
            cap = cv2.VideoCapture(idx)
            if cap.isOpened():
                cap.set(cv2.CAP_PROP_FRAME_WIDTH, config.DEFAULT_FRAME_WIDTH)
                cap.set(cv2.CAP_PROP_FRAME_HEIGHT, config.DEFAULT_FRAME_HEIGHT)
                cap.set(cv2.CAP_PROP_FPS, config.DEFAULT_FPS)
                self._capture = cap
                self._active_camera_index = idx
                return idx
            cap.release()

        raise RecorderError(
            "No camera could be opened. Please check that a webcam or your "
            "laptop's built-in camera is connected, not disabled in the OS, "
            "and not already in use by another application."
        )

    def read_preview_frame(self):
        """
        Read a single frame for the live preview, without writing it to
        disk or affecting the evidence pipeline in any way. Safe to call
        repeatedly on a GUI timer whenever a recording is not in progress.
        """
        if self._is_recording or self._capture is None:
            return None

        success, frame = self._capture.read()
        if not success:
            return None
        return frame

    def close_preview(self):
        """Release the camera used for preview, if one is open and not recording."""
        if self._is_recording:
            return
        if self._capture is not None:
            self._capture.release()
        self._capture = None
        self._active_camera_index = None

    def start_recording(self, filename: str = None) -> str:
        """
        Begin recording. Location must already have been resolved via
        check_location_or_raise() by the caller (the GUI enforces this by
        disabling the Record button until location succeeds).
        """
        if self._is_recording:
            raise RecorderError("A recording is already in progress.")

        if self._location_result is None:
            # Defensive check -- the GUI should never allow this, but the
            # module itself must never produce evidence without location.
            raise RecorderError(
                "Location access is required to record evidence. "
                "Please enable location services and try again."
            )

        # Reuse the already-open preview camera if there is one (the normal
        # path: the GUI opened a live preview as soon as location resolved).
        # Falls back to opening one now if a preview wasn't already running.
        self.open_camera_for_preview()

        actual_width = int(self._capture.get(cv2.CAP_PROP_FRAME_WIDTH)) or config.DEFAULT_FRAME_WIDTH
        actual_height = int(self._capture.get(cv2.CAP_PROP_FRAME_HEIGHT)) or config.DEFAULT_FRAME_HEIGHT

        if not filename:
            timestamp_tag = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"evidence_{timestamp_tag}{config.VIDEO_EXTENSION}"

        self._output_path = os.path.join(config.VIDEOS_DIR, filename)

        fourcc = cv2.VideoWriter_fourcc(*config.VIDEO_FOURCC)
        self._writer = cv2.VideoWriter(
            self._output_path, fourcc, config.DEFAULT_FPS, (actual_width, actual_height)
        )

        if not self._writer.isOpened():
            raise RecorderError("Failed to initialize video writer.")

        self._hash_chain.reset()

        now_local = datetime.datetime.now().astimezone()
        self._start_time_local = now_local
        self._start_time_utc = now_local.astimezone(datetime.timezone.utc)

        self._is_recording = True
        return self._output_path

    def read_frame(self):
        """
        Read a single frame, write it to disk, and feed it into the hash
        chain. Returns the frame (numpy array) for GUI preview, or None if
        the capture failed.

        The GUI is expected to call this repeatedly on a timer while
        `is_recording` is True.
        """
        if not self._is_recording or self._capture is None:
            return None

        success, frame = self._capture.read()
        if not success:
            return None

        self._writer.write(frame)
        # NOTE: we deliberately do NOT hash the raw frame buffer here.
        # The hash chain is computed once, after the file is fully written
        # and closed, by decoding it back with OpenCV (see stop_recording).
        # Hashing pre-encode bytes here and comparing them at verify time
        # against post-decode bytes would fail on every recording due to
        # the video codec changing pixel bytes, even with zero tampering.

        return frame

    def stop_recording(self, evidence_passphrase: str) -> dict:
        """
        Stop recording, release camera/writer resources, build and embed
        the evidence package, and persist a database record.

        Args:
            evidence_passphrase: Passphrase used to AES-encrypt the
                evidence metadata package (separate from the private-key
                unlock password, though the GUI may reuse the same value
                for simplicity in the MVP).

        Returns:
            A dict summary of the evidence that was created.
        """
        if not self._is_recording:
            raise RecorderError("No recording is currently in progress.")

        self._is_recording = False

        used_camera_index = self._active_camera_index if self._active_camera_index is not None else self._camera_index

        # IMPORTANT: query the backend name BEFORE releasing the capture.
        # Once VideoCapture.release() is called, the underlying capture
        # API pointer is torn down and getBackendName() raises a hard
        # cv2.error (Assertion failed: api != 0). Grabbing it first avoids
        # that crash, which previously aborted stop_recording() partway
        # through -- before signing, encryption, embedding, or the
        # database write ever ran (hence evidence/location/hash fields
        # showing up empty or "failed" afterwards).
        backend_name = "unknown"
        if self._capture is not None:
            try:
                backend_name = self._capture.getBackendName()
            except Exception:
                backend_name = "unknown"
            self._capture.release()
        self._capture = None
        self._active_camera_index = None
        if self._writer is not None:
            self._writer.release()

        camera_info = {
            "camera_index": used_camera_index,
            "backend": backend_name,
        }

        # Compute the frame hash chain by decoding the *finished* video file,
        # the same way verification.py will later re-decode it. This is what
        # makes the recorded hash and the recomputed hash at verify time
        # actually comparable (see hash_chain.compute_chain_from_video).
        #
        # compute_full_chain_from_video() also builds a Merkle tree over
        # each frame's own (unchained) hash, and -- if the optional
        # `imagehash` package is installed -- a per-frame perceptual hash.
        # See config.py's "Frame-level tamper localization & perceptual
        # hashing" section for why: this lets verification later report
        # *which* frames differ on a mismatch, and distinguish ordinary
        # re-encoding from actual content tampering, instead of only a
        # blunt "chain broken" result.
        full_chain = compute_full_chain_from_video(self._output_path)
        final_hash_hex = full_chain["final_hash_hex"]
        frame_count = full_chain["frame_count"]
        self._hash_chain.reset()

        frame_hash_chain_payload = {
            "algorithm": "SHA-256 (chained)",
            "frame_count": frame_count,
            "final_hash": final_hash_hex,
            "merkle_algorithm": "SHA-256 (binary Merkle tree, odd node self-paired)",
            "merkle_root": full_chain["merkle_root_hex"],
            "frame_leaf_hashes_b64": base64.b64encode(
                b"".join(full_chain["frame_leaf_hashes"])
            ).decode("ascii"),
        }
        if full_chain["perceptual_hashes"] is not None:
            frame_hash_chain_payload["perceptual_hash_algorithm"] = (
                f"pHash-{config.PERCEPTUAL_HASH_SIZE_BYTES * 8}bit"
            )
            frame_hash_chain_payload["perceptual_hashes_b64"] = base64.b64encode(
                b"".join(full_chain["perceptual_hashes"])
            ).decode("ascii")

        evidence_payload = {
            "app_version": config.APP_VERSION,
            "gps": self._location_result.to_dict(),
            "timestamp": {
                "date": self._start_time_local.strftime("%Y-%m-%d"),
                "time": self._start_time_local.strftime("%H:%M:%S"),
                "utc_offset": self._start_time_local.strftime("%z"),
                "start_time_utc_iso": self._start_time_utc.isoformat(),
            },
            "frame_hash_chain": frame_hash_chain_payload,
            "camera_info": camera_info,
        }

        # ------------------------------------------------------------
        # RFC 3161 trusted timestamp (optional, purely additive -- see
        # crypto_core.py's "RFC 3161 trusted timestamping" section for the
        # full rationale). This asks an independent, third-party Time-Stamp
        # Authority to attest that final_hash_hex existed by a given time,
        # using the TSA's own clock rather than this machine's local clock
        # (which the "timestamp" field above relies on, and which anyone
        # can change before recording). Deliberately done BEFORE signing
        # below so the token becomes part of what the ECC signature covers.
        #
        # If the TSA can't be reached (offline recording, firewall, package
        # not installed, TSA downtime), this is silently skipped -- the
        # recording is never blocked or lost because of it, exactly like
        # the LSB/chunk steganographic references further down.
        # ------------------------------------------------------------
        if getattr(config, "TSA_ENABLED", True):
            try:
                token_bytes = request_trusted_timestamp(bytes.fromhex(final_hash_hex))
                evidence_payload["rfc3161_timestamp"] = {
                    "tsa_url": config.TSA_URL,
                    "hash_algorithm": config.TSA_HASH_ALGORITHM,
                    "token_b64": base64.b64encode(token_bytes).decode("ascii"),
                }
            except TimestampError as exc:
                logger.warning("RFC 3161 trusted timestamp unavailable for this recording: %s", exc)

        # Sign the canonical evidence payload before encryption so the
        # signature covers the exact plaintext metadata.
        #
        # Everything from here through embed_payload() below is wrapped in
        # a try/except: if signing fails (e.g. the private key won't
        # unlock), or encryption/embedding fails for any reason, we would
        # otherwise be left with a fully-written, playable .mp4 sitting in
        # VIDEOS_DIR that looks like valid evidence but has no embedded
        # evidence package at all -- confusing (or worse, misleading)
        # during later verification. On any failure here we delete that
        # incomplete file instead of leaving it behind, then re-raise as a
        # RecorderError so the GUI can report it clearly.
        import json

        try:
            canonical_bytes = json.dumps(evidence_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            signature = self._key_manager.sign(canonical_bytes)
            evidence_payload["signature_hex"] = signature.hex()
            evidence_payload["public_key_pem"] = self._key_manager.get_public_key_pem().decode("utf-8")

            encrypted_blob = encrypt_json(evidence_payload, evidence_passphrase)
            embed_payload(self._output_path, encrypted_blob)
            # Companion .crygan sidecar file (see evidence_storage.py's
            # "Companion .crygan evidence file" section): the mechanism
            # that actually matters for handing evidence to someone else
            # -- a court, a forensic lab, another investigator -- since it
            # travels with the video as an ordinary file and survives
            # transcoding, unlike in-file embedding or the local registry.
            # Treated as mandatory (same as embedding itself, above)
            # rather than a best-effort extra: silently missing this file
            # would only be discovered later, when it's needed most.
            write_companion_file(self._output_path, encrypted_blob)
        except Exception as exc:
            if self._output_path and os.path.exists(self._output_path):
                try:
                    os.remove(self._output_path)
                except OSError:
                    pass
            self._output_path = None
            self._location_result = None
            raise RecorderError(
                f"Failed to finalize evidence for this recording (signing/encryption/"
                f"embedding step): {exc}. The incomplete video file has been deleted "
                f"rather than left behind without embedded evidence."
            ) from exc

        evidence_id = self._db.create_evidence_record(
            video_filename=os.path.basename(self._output_path),
            video_path=self._output_path,
            recorded_at_utc=self._start_time_utc.isoformat(),
            latitude=self._location_result.latitude,
            longitude=self._location_result.longitude,
            frame_count=frame_count,
            final_hash=final_hash_hex,
        )

        # Raw-byte form of this recording's own unique evidence_id, for
        # embedding into the LSB reference frame and RS chunk frames below
        # (see evidence_storage.py's discover_evidence_pngs()). Using this
        # same ID as the filename base for those PNGs too means recovery
        # no longer depends on the video's filename staying unchanged --
        # both the pixel content AND the filename now key off the
        # recording's own stable ID rather than the video's current name.
        evidence_id_bytes = uuid.UUID(evidence_id).bytes

        # ------------------------------------------------------------
        # Local out-of-band evidence registry (see config.py's "Local
        # perceptual-hash evidence registry" section). Stores an
        # independent copy of the encrypted evidence + a compact
        # perceptual fingerprint in this machine's own local database --
        # not inside the video file -- so verification can still recover
        # the signed evidence later even from a copy of this video that's
        # been transcoded/re-encoded and has nothing embedded left at
        # all. Purely additive: the video file and its embedded evidence
        # are already complete at this point, so a failure here (e.g. a
        # locked database file) is logged and never blocks the recording.
        # ------------------------------------------------------------
        try:
            if full_chain["perceptual_hashes"]:
                fingerprint = sample_fingerprint(full_chain["perceptual_hashes"])
                self._db.add_registry_entry(
                    evidence_id=evidence_id,
                    recorded_at_utc=self._start_time_utc.isoformat(),
                    frame_count=frame_count,
                    final_hash=final_hash_hex,
                    merkle_root=full_chain["merkle_root_hex"],
                    fingerprint_b64=base64.b64encode(fingerprint).decode("ascii"),
                    encrypted_payload_b64=base64.b64encode(encrypted_blob).decode("ascii"),
                )
        except Exception as exc:
            logger.warning("Could not write local out-of-band evidence registry entry: %s", exc)

        # ------------------------------------------------------------
        # Genuine pixel-domain (LSB) steganographic reference (hybrid
        # design -- see evidence_storage.py's "LSB" section for the full
        # rationale). This is purely additive: the .mp4 file, its
        # embedded evidence package, and its recorded chain hash above
        # are already complete and valid at this point. If anything
        # below fails, we log it and continue -- an evidence recording
        # should never be lost or corrupted just because the *bonus*
        # LSB reference frame couldn't be generated.
        # ------------------------------------------------------------
        stego_reference_path = None
        try:
            probe_capture = cv2.VideoCapture(self._output_path, cv2.CAP_FFMPEG)
            if not probe_capture.isOpened():
                probe_capture = cv2.VideoCapture(self._output_path)
            success, first_frame = probe_capture.read()
            probe_capture.release()

            if success:
                reference_bytes = pack_reference(bytes.fromhex(final_hash_hex), signature)
                lsb_frame = embed_lsb_reference(first_frame, evidence_id_bytes, reference_bytes)

                stego_reference_path = os.path.join(
                    config.STEGO_REFERENCE_DIR, f"{evidence_id}_stego_ref.png"
                )
                # PNG is lossless, so every LSB we just set survives on disk
                # exactly as written -- unlike the lossy .mp4 video itself.
                cv2.imwrite(stego_reference_path, lsb_frame)
        except EvidenceStorageError:
            stego_reference_path = None
        except Exception:
            stego_reference_path = None

        # ------------------------------------------------------------
        # Reed-Solomon erasure-coded chunk reference frames (see
        # evidence_storage.py's "erasure-coded chunk" section for the full
        # rationale). Unlike the single-frame reference above (which only
        # covers the final hash + signature), this spreads the ENTIRE
        # encrypted evidence blob across config.STEGO_CHUNK_DATA_COUNT +
        # config.STEGO_CHUNK_PARITY_COUNT reference frames, such that any
        # config.STEGO_CHUNK_DATA_COUNT of them are enough to reconstruct
        # the full evidence package -- even if the primary tail-appended
        # payload on the video itself is later truncated/corrupted, and
        # even if some of these reference frames are also lost.
        #
        # Also purely additive: any failure here (reedsolo missing, video
        # too short to spread chunks across, etc.) is swallowed and simply
        # leaves this recording without the extra resilience, exactly like
        # the single-frame reference above.
        # ------------------------------------------------------------
        stego_chunk_paths = []
        try:
            num_data = config.STEGO_CHUNK_DATA_COUNT
            num_parity = config.STEGO_CHUNK_PARITY_COUNT
            total_needed = num_data + num_parity

            chunks = erasure_encode(encrypted_blob, num_data, num_parity)
            target_indices = pick_evenly_spaced_frame_indices(frame_count, total_needed)

            if len(target_indices) == total_needed:
                probe_capture = cv2.VideoCapture(self._output_path, cv2.CAP_FFMPEG)
                if not probe_capture.isOpened():
                    probe_capture = cv2.VideoCapture(self._output_path)

                target_set = set(target_indices)
                chunk_index_by_frame = {frame_idx: i for i, frame_idx in enumerate(target_indices)}

                current_frame_num = 0
                found = 0
                while found < total_needed:
                    success, frame = probe_capture.read()
                    if not success:
                        break
                    if current_frame_num in target_set:
                        chunk_i = chunk_index_by_frame[current_frame_num]
                        chunk_frame = embed_chunk_into_frame(
                            frame, evidence_id_bytes, chunk_i, total_needed, num_data, chunks[chunk_i]
                        )
                        chunk_path = os.path.join(
                            config.STEGO_REFERENCE_DIR,
                            f"{evidence_id}_chunk_{chunk_i:03d}_of_{total_needed:03d}.png",
                        )
                        cv2.imwrite(chunk_path, chunk_frame)
                        stego_chunk_paths.append(chunk_path)
                        found += 1
                    current_frame_num += 1

                probe_capture.release()
        except EvidenceStorageError:
            stego_chunk_paths = []
        except Exception:
            stego_chunk_paths = []

        summary = {
            "evidence_id": evidence_id,
            "video_path": self._output_path,
            "frame_count": frame_count,
            "final_hash": final_hash_hex,
            "location": self._location_result.to_dict(),
            "start_time_local": self._start_time_local.isoformat(),
            "stego_reference_path": stego_reference_path,
            "stego_chunk_paths": stego_chunk_paths,
        }

        # Reset session state so the recorder can be reused for a new take.
        self._location_result = None
        self._output_path = None

        return summary

    def cancel_recording(self):
        """Abort an in-progress recording and discard the partial file."""
        self._is_recording = False
        if self._capture is not None:
            self._capture.release()
        self._capture = None
        self._active_camera_index = None
        if self._writer is not None:
            self._writer.release()
        if self._output_path and os.path.exists(self._output_path):
            try:
                os.remove(self._output_path)
            except OSError:
                pass
        self._output_path = None
        self._location_result = None

# ==========================================================================
# Originally: app_state.py
# ==========================================================================
"""
app_state.py
------------
Small shared-state container passed between GUI views.

Holds the in-memory (never persisted) key/evidence password for the
current session and the lazily-created KeyManager instance, so the user
only has to unlock their key once per application run.
"""



class AppState:
    """Session-scoped state shared across the main window's views."""

    def __init__(self, theme_manager=None):
        self.session_password: str = ""
        self._key_manager: KeyManager = None
        self.camera_index: int = config.DEFAULT_CAMERA_INDEX
        # Shared ThemeManager instance (see theme.py), so any view can read
        # the current theme or let the user change it (currently exposed
        # in Settings).
        self.theme_manager = theme_manager

        # If a password was remembered from a previous run (see
        # py), silently unlock the keys with it now, so the user
        # doesn't have to re-enter it in Settings every single launch.
        # Any failure here (corrupted remember-store, keys deleted since,
        # etc.) is treated as "nothing remembered" -- the user just falls
        # back to entering the password manually, same as before this
        # feature existed.
        self._try_auto_unlock()

    def _try_auto_unlock(self):
        remembered_password = load_password()
        if not remembered_password:
            return
        try:
            self.set_password(remembered_password, _remember=False)
        except KeyManagerError:
            pass

    def has_password(self) -> bool:
        return bool(self.session_password)

    def set_password(self, password: str, _remember: bool = True):
        # Build against a local variable first (not self._key_manager) so
        # that if the password is wrong for an already-existing key file,
        # we raise here -- immediately, in Settings -- and leave any prior
        # working session_password/_key_manager untouched, rather than
        # silently adopting a broken key manager that will only fail much
        # later when a recording is stopped.
        key_manager = KeyManager(password=password)
        key_manager.ensure_keys_exist()
        key_manager.unlock()  # raises KeyManagerError now if password is wrong

        self.session_password = password
        self._key_manager = key_manager

        if _remember:
            # Best-effort: remembering the password is a convenience, not
            # a requirement, so a failure to persist it should never break
            # unlocking itself.
            try:
                save_password(password)
            except Exception:
                pass

    def regenerate_keys(self, password: str):
        """
        Force-create a brand new key pair protected by `password`,
        overwriting any existing key files. Used by the "Regenerate Keys"
        action in Settings.
        """
        key_manager = KeyManager(password=password)
        key_manager.regenerate_keys()
        self.session_password = password
        self._key_manager = key_manager
        try:
            save_password(password)
        except Exception:
            pass

    def forget_saved_password(self):
        """
        Clear any remembered password (see py) without touching
        the actual key files or the current in-memory session. Used by
        the "Forget Saved Password" action in Settings.
        """
        clear_password()

    def get_key_manager(self) -> KeyManager:
        if self._key_manager is None:
            raise RuntimeError("Key manager not initialized. Set a password first in Settings.")
        return self._key_manager

# ==========================================================================
# Originally: report.py
# ==========================================================================
"""
report.py
---------
Generates a PDF evidence report summarizing a verification run, using
reportlab. The report is intended as a human-readable, shareable summary
of Project Crygan's cryptographic findings -- it is not itself a source of
truth (the video + embedded evidence package remains that), but a
convenient artifact for sharing with third parties.
"""





def _status_text(ok: bool) -> str:
    return "PASSED" if ok else "FAILED"


def _status_color(ok: bool):
    return colors.HexColor("#1a7f37") if ok else colors.HexColor("#c62828")


def generate_report(
    evidence_id: str,
    video_filename: str,
    verification_result,
    output_path: str = None,
) -> str:
    """
    Build a PDF report from a VerificationResult (see verification.py).

    Returns:
        The path to the generated PDF file.
    """
    if output_path is None:
        safe_id = evidence_id[:8] if evidence_id else "unknown"
        timestamp_tag = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(config.REPORTS_DIR, f"report_{safe_id}_{timestamp_tag}.pdf")

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "CryganTitle", parent=styles["Title"], fontSize=20, spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        "CryganSubtitle", parent=styles["Normal"], textColor=colors.grey, spaceAfter=18
    )
    heading_style = ParagraphStyle(
        "CryganHeading", parent=styles["Heading2"], spaceBefore=16, spaceAfter=8
    )
    normal_style = styles["Normal"]
    link_style = ParagraphStyle(
        "CryganLink", parent=styles["Normal"], textColor=colors.HexColor("#2f80ed"), spaceBefore=4
    )

    payload = verification_result.evidence_payload or {}
    gps = payload.get("gps", {})
    timestamp = payload.get("timestamp", {})

    doc = SimpleDocTemplate(
        output_path,
        pagesize=LETTER,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
    )

    elements = []

    elements.append(Paragraph(f"{config.APP_NAME} -- Evidence Verification Report", title_style))
    elements.append(
        Paragraph(
            f"Generated {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} "
            f"&bull; {config.APP_NAME} v{config.APP_VERSION}",
            subtitle_style,
        )
    )

    # --- Evidence identification -----------------------------------
    elements.append(Paragraph("Evidence Identification", heading_style))
    id_table_data = [
        ["Evidence ID", evidence_id or "N/A"],
        ["Video File", video_filename or "N/A"],
        ["Recording Date", timestamp.get("date", "N/A")],
        ["Recording Time", timestamp.get("time", "N/A")],
        ["UTC Offset", timestamp.get("utc_offset", "N/A")],
    ]
    elements.append(_make_kv_table(id_table_data))

    # --- Location -----------------------------------------------------
    elements.append(Paragraph("Recording Location", heading_style))
    accuracy = gps.get("accuracy_meters")
    location_table_data = [
        ["Latitude", str(gps.get("latitude", "N/A"))],
        ["Longitude", str(gps.get("longitude", "N/A"))],
        ["City", gps.get("city", "N/A")],
        ["Country", gps.get("country", "N/A")],
        ["Location Source", gps.get("source", "N/A")],
        ["Accuracy (radius)", f"~{accuracy:.0f} m" if accuracy else "N/A (source does not report accuracy)"],
    ]
    elements.append(_make_kv_table(location_table_data))

    latitude = gps.get("latitude")
    longitude = gps.get("longitude")
    if latitude is not None and longitude is not None:
        maps_url = build_maps_url(latitude, longitude)
        elements.append(
            Paragraph(
                f'<link href="{maps_url}">View this location on Google Maps &rarr;</link>',
                link_style,
            )
        )

    # --- Verification results -----------------------------------------
    elements.append(Paragraph("Verification Results", heading_style))

    result_rows = [
        ["Check", "Status"],
        ["Evidence Source", verification_result.evidence_source],
        ["Evidence Package Found", _status_text(verification_result.evidence_found)],
        ["Metadata Decryption", _status_text(verification_result.decryption_ok)],
        ["Digital Signature", _status_text(verification_result.signature_ok)],
        ["Frame Hash Chain", _status_text(verification_result.chain_ok)],
    ]
    if getattr(verification_result, "merkle_checked", False):
        result_rows.append(
            ["Merkle Frame Commitment (optional)", _status_text(verification_result.merkle_ok)]
        )
    if getattr(verification_result, "lsb_reference_checked", False):
        result_rows.append(
            ["LSB Steganographic Reference (optional)", _status_text(verification_result.lsb_reference_ok)]
        )
    if getattr(verification_result, "timestamp_checked", False):
        result_rows.append(
            ["RFC 3161 Trusted Timestamp (optional)", _status_text(verification_result.timestamp_ok)]
        )
    result_rows.append(["Overall Integrity", _status_text(verification_result.overall_integrity_ok)])
    result_table = Table(result_rows, colWidths=[3 * inch, 2.5 * inch])
    result_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2b2d42")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    elements.append(result_table)
    elements.append(Spacer(1, 12))

    # --- Frame chain detail --------------------------------------------
    elements.append(Paragraph("Frame Hash Chain Detail", heading_style))
    chain_table_data = [
        ["Recorded Frame Count", str(verification_result.recorded_frame_count)],
        ["Recomputed Frame Count", str(verification_result.recomputed_frame_count)],
        ["Recorded Final Hash", verification_result.recorded_final_hash or "N/A"],
        ["Recomputed Final Hash", verification_result.recomputed_final_hash or "N/A"],
    ]
    elements.append(_make_kv_table(chain_table_data))

    # --- Merkle tamper-localization detail -------------------------------
    if getattr(verification_result, "merkle_checked", False) and not verification_result.merkle_ok:
        elements.append(Paragraph("Frame-Level Tamper Localization (Merkle)", heading_style))
        indices_str = ", ".join(str(i) for i in verification_result.tampered_frame_indices) or "N/A"
        if verification_result.tampered_frame_indices_truncated:
            indices_str += ", ... (list truncated)"
        if verification_result.perceptual_hashing_available:
            transcoded_str = ", ".join(str(i) for i in verification_result.transcoded_frame_indices) or "none"
            altered_str = ", ".join(str(i) for i in verification_result.content_altered_frame_indices) or "none"
        else:
            transcoded_str = "N/A (perceptual hashing unavailable)"
            altered_str = "N/A (perceptual hashing unavailable)"
        merkle_table_data = [
            ["Differing Frame Indices", indices_str],
            ["  -> Consistent with re-encoding only", transcoded_str],
            ["  -> Content likely changed", altered_str],
        ]
        elements.append(_make_kv_table(merkle_table_data))
        elements.append(
            Paragraph(
                "The frames listed above are the specific ones whose content hash no "
                "longer matches what was recorded at capture time. Where perceptual "
                "hashing was available, it was used to estimate whether these "
                "differences look like ordinary lossy re-encoding (e.g. re-uploading "
                "to a messaging app) rather than a genuine content change -- this is a "
                "corroborating signal only, not independent proof of authenticity.",
                normal_style,
            )
        )

    # --- Trusted timestamp detail ---------------------------------------
    if getattr(verification_result, "timestamp_checked", False):
        elements.append(Paragraph("Trusted Timestamp Detail (RFC 3161)", heading_style))
        timestamp_table_data = [
            ["Time-Stamp Authority", verification_result.tsa_url or "N/A"],
            ["TSA-Attested Time (UTC)", verification_result.tsa_timestamp_utc or "N/A"],
            ["Verification Result", _status_text(verification_result.timestamp_ok)],
        ]
        elements.append(_make_kv_table(timestamp_table_data))
        elements.append(
            Paragraph(
                "This is an independent, third-party attestation that the recorded "
                "final hash existed by the time shown above, obtained from the named "
                "Time-Stamp Authority's own clock -- not the recording device's local "
                "clock. It corroborates, but does not replace, the capture timestamp "
                "reported earlier in this document.",
                normal_style,
            )
        )

    # --- Failure explanation --------------------------------------------
    if verification_result.failure_reasons:
        elements.append(Paragraph("Issues Detected", heading_style))
        for reason in verification_result.failure_reasons:
            elements.append(Paragraph(f"&bull; {reason}", normal_style))

    elements.append(Spacer(1, 20))
    elements.append(
        Paragraph(
            "This report was generated automatically by Project Crygan. "
            "It reflects cryptographic verification performed against the "
            "evidence package embedded in the referenced video file at the "
            "time of generation.",
            ParagraphStyle("Footer", parent=normal_style, textColor=colors.grey, fontSize=8),
        )
    )

    doc.build(elements)
    return output_path


def _make_kv_table(rows) -> Table:
    table = Table(rows, colWidths=[2 * inch, 4 * inch])
    table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    return table

# ==========================================================================
# Originally: main_window.py
# ==========================================================================
"""
main_window.py
---------------
Top-level PySide6 main window for Project Crygan.

Provides a simple sidebar navigation between the four primary screens:
Record Video, Verify Video, Evidence Reports, and Settings. Each screen is
implemented in its own module (record_view.py, verify_view.py,
reports_view.py, settings_view.py) to keep this file focused purely on
window chrome and navigation.

Theming: this window does not hard-code any colors itself. Every widget
is tagged with a semantic `class` property (see theme.set_class) and the
actual colors come from the single global stylesheet installed by
ThemeManager (theme.py), which supports light mode, dark mode, and
following the OS theme automatically -- switchable live from Settings.
"""




class MainWindow(QMainWindow):
    """Application shell: sidebar navigation + stacked content area."""

    def __init__(self, theme_manager):
        super().__init__()
        self.setWindowTitle(f"{config.APP_NAME} v{config.APP_VERSION}")
        self.resize(1100, 720)

        self.app_state = AppState(theme_manager=theme_manager)

        central = QWidget()
        self.setCentralWidget(central)

        root_layout = QHBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # ---------------- Sidebar ----------------
        sidebar = QFrame()
        sidebar.setFixedWidth(220)
        set_class(sidebar, "sidebar")

        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        sidebar_layout.setSpacing(0)

        title_label = QLabel(f"  {config.APP_NAME}")
        set_class(title_label, "sidebar-title")
        title_label.setStyleSheet("padding: 24px 10px 8px 12px;")
        title_font = QFont()
        title_font.setPointSize(15)
        title_font.setBold(True)
        title_label.setFont(title_font)
        sidebar_layout.addWidget(title_label)

        version_label = QLabel(f"  Version {config.APP_VERSION}")
        set_class(version_label, "sidebar-version")
        version_label.setStyleSheet("padding: 0 10px 20px 12px;")
        sidebar_layout.addWidget(version_label)

        self.nav_buttons = {}
        nav_items = [
            ("record", "Record Video"),
            ("verify", "Verify Video"),
            ("reports", "Evidence Reports"),
            ("settings", "Settings"),
        ]
        for key, label in nav_items:
            btn = QPushButton(label)
            btn.setCheckable(True)
            btn.clicked.connect(lambda checked, k=key: self._navigate(k))
            sidebar_layout.addWidget(btn)
            self.nav_buttons[key] = btn

        sidebar_layout.addStretch()
        root_layout.addWidget(sidebar)

        # ---------------- Content area ----------------
        self.stack = QStackedWidget()

        self.record_view = RecordView(self.app_state)
        self.verify_view = VerifyView(self.app_state)
        self.reports_view = ReportsView(self.app_state)
        self.settings_view = SettingsView(self.app_state)

        self.views = {
            "record": self.record_view,
            "verify": self.verify_view,
            "reports": self.reports_view,
            "settings": self.settings_view,
        }
        for view in self.views.values():
            self.stack.addWidget(view)

        root_layout.addWidget(self.stack, stretch=1)

        # Refresh reports list whenever it becomes visible.
        self.stack.currentChanged.connect(self._on_stack_changed)

        self._navigate("record")

    def _navigate(self, key: str):
        for nav_key, btn in self.nav_buttons.items():
            btn.setChecked(nav_key == key)
        self.stack.setCurrentWidget(self.views[key])

    def _on_stack_changed(self, index: int):
        current = self.stack.widget(index)
        if current is self.reports_view:
            self.reports_view.refresh()

    def closeEvent(self, event):
        # Ensure the camera is released if the window is closed mid-recording.
        try:
            self.record_view.shutdown()
        except Exception:
            pass
        super().closeEvent(event)

# ==========================================================================
# Originally: record_view.py
# ==========================================================================
"""
record_view.py
---------------
GUI screen for recording evidence video. Wires the VideoRecorder
(recorder.py) to a live camera preview and enforces the mandatory
location-check-before-recording policy described in the project spec.
"""





class RecordView(QWidget):
    def __init__(self, app_state):
        super().__init__()
        self.app_state = app_state
        self.recorder = None  # created lazily once a password/key is set

        self.preview_timer = QTimer(self)
        self.preview_timer.setInterval(33)  # ~30 FPS
        self.preview_timer.timeout.connect(self._on_timer_tick)
        self._consecutive_frame_failures = 0

        self._build_ui()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(16)

        heading = QLabel("Record Video")
        set_class(heading, "heading")
        layout.addWidget(heading)

        subheading = QLabel(
            "Location access is required before recording can begin. "
            "This guarantees every recording carries verifiable GPS evidence."
        )
        subheading.setWordWrap(True)
        set_class(subheading, "subheading")
        layout.addWidget(subheading)

        # Camera selector -- lets the user manually switch cameras (e.g.
        # away from a virtual-camera app like Iriun once the phone
        # disconnects). This is the only place in the app camera switching
        # is available (Settings no longer has its own copy of this).
        camera_row = QHBoxLayout()
        camera_label = QLabel("Camera:")
        self.camera_combo = QComboBox()
        self.camera_combo.setMinimumWidth(200)
        self.camera_combo.currentIndexChanged.connect(self._on_camera_combo_changed)

        camera_row.addWidget(camera_label)
        camera_row.addWidget(self.camera_combo, stretch=1)
        layout.addLayout(camera_row)

        self._populate_camera_combo()

        # Preview frame
        self.preview_frame = QFrame()
        set_class(self.preview_frame, "preview")
        self.preview_frame.setMinimumHeight(420)
        preview_layout = QVBoxLayout(self.preview_frame)
        self.preview_label = QLabel("Camera preview will appear here")
        self.preview_label.setAlignment(Qt.AlignCenter)
        set_class(self.preview_label, "preview-placeholder")
        preview_layout.addWidget(self.preview_label)
        layout.addWidget(self.preview_frame, stretch=1)

        # Status label
        self.status_label = QLabel("Status: Idle")
        self.status_label.setWordWrap(True)
        set_class(self.status_label, "status")
        layout.addWidget(self.status_label)

        # Controls
        controls = QHBoxLayout()
        self.check_location_btn = QPushButton("Check Location")
        self.check_location_btn.clicked.connect(self._on_check_location)

        self.start_btn = QPushButton("Start Recording")
        self.start_btn.setEnabled(False)
        self.start_btn.clicked.connect(self._on_start_recording)

        self.stop_btn = QPushButton("Stop && Save")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._on_stop_recording)

        for btn in (self.check_location_btn, self.start_btn, self.stop_btn):
            btn.setMinimumHeight(40)
            set_class(btn, "primary")
            controls.addWidget(btn)

        layout.addLayout(controls)

    # ------------------------------------------------------------------
    # Location check
    # ------------------------------------------------------------------
    def _on_check_location(self):
        if not self.app_state.has_password():
            QMessageBox.warning(
                self,
                "Set Up Security First",
                "Please open Settings and set your key/evidence password before recording.",
            )
            return

        self.status_label.setText("Status: Resolving location...")
        self._ensure_recorder()

        try:
            location = self.recorder.check_location_or_raise()
        except LocationError as exc:
            self.start_btn.setEnabled(False)
            QMessageBox.critical(self, "Location Required", str(exc))
            self.status_label.setText("Status: Location unavailable. Recording disabled.")
            return

        # Location is resolved -- open the camera now so the user can see
        # and frame their shot *before* committing to Start Recording,
        # rather than only finding out what the camera sees once recording
        # (and hashing/writing to disk) has already begun.
        try:
            used_index = self.recorder.open_camera_for_preview()
        except RecorderError as exc:
            self.start_btn.setEnabled(False)
            QMessageBox.critical(self, "Camera Error", str(exc))
            self.status_label.setText("Status: Camera unavailable. Recording disabled.")
            return

        self._consecutive_frame_failures = 0
        self.preview_timer.start()

        camera_note = ""
        if used_index != self.app_state.camera_index:
            camera_note = (
                f" (using camera {used_index} -- the configured camera "
                f"{self.app_state.camera_index} wasn't available)"
            )

        self.status_label.setText(
            f"Status: Location resolved ({location.city or 'unknown city'}, "
            f"{location.country or 'unknown country'}) -- camera preview ready{camera_note}."
        )
        self.start_btn.setEnabled(True)

    def _ensure_recorder(self):
        if self.recorder is None:
            self.recorder = VideoRecorder(
                key_manager=self.app_state.get_key_manager(),
                camera_index=self.app_state.camera_index,
            )

    # ------------------------------------------------------------------
    # Camera selection
    # ------------------------------------------------------------------
    def _populate_camera_combo(self):
        cameras = VideoRecorder.list_available_cameras_with_names()
        self.camera_combo.blockSignals(True)
        self.camera_combo.clear()
        if not cameras:
            self.camera_combo.addItem("No camera detected", -1)
        else:
            for idx, name in cameras:
                self.camera_combo.addItem(name, idx)
            match_pos = self.camera_combo.findData(self.app_state.camera_index)
            self.camera_combo.setCurrentIndex(match_pos if match_pos >= 0 else 0)
        self.camera_combo.blockSignals(False)

    def _sync_camera_combo_to_current(self):
        self.camera_combo.blockSignals(True)
        match_pos = self.camera_combo.findData(self.app_state.camera_index)
        if match_pos >= 0:
            self.camera_combo.setCurrentIndex(match_pos)
        self.camera_combo.blockSignals(False)

    def _on_camera_combo_changed(self, _index: int):
        value = self.camera_combo.currentData()
        if value is None or value < 0:
            return

        if self.recorder is not None and self.recorder.is_recording:
            QMessageBox.warning(
                self,
                "Recording in Progress",
                "Stop the current recording before switching cameras.",
            )
            self._sync_camera_combo_to_current()
            return

        self.app_state.camera_index = value
        if self.recorder is None:
            return  # will be picked up whenever the recorder is created

        self.recorder.set_camera_index(value)
        self.recorder.close_preview()
        self._consecutive_frame_failures = 0

        try:
            self.recorder.open_camera_for_preview()
            if not self.preview_timer.isActive():
                self.preview_timer.start()
            self.status_label.setText(
                f"Status: Switched to {self.camera_combo.currentText()} -- preview ready."
            )
        except RecorderError as exc:
            self.start_btn.setEnabled(False)
            QMessageBox.critical(self, "Camera Error", str(exc))
            self.status_label.setText("Status: Camera unavailable.")

    # ------------------------------------------------------------------
    # Recording controls
    # ------------------------------------------------------------------
    def _on_start_recording(self):
        try:
            self.recorder.start_recording()
        except RecorderError as exc:
            QMessageBox.critical(self, "Recording Error", str(exc))
            return

        self.start_btn.setEnabled(False)
        self.check_location_btn.setEnabled(False)
        self.camera_combo.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("Status: Recording...")
        # preview_timer is already running (started once location/camera
        # were confirmed in _on_check_location); no need to start it again.

    def _on_timer_tick(self):
        if self.recorder.is_recording:
            frame = self.recorder.read_frame()
        else:
            frame = self.recorder.read_preview_frame()

        if frame is None:
            self._consecutive_frame_failures += 1
            # If frames stop coming for about half a second while we're
            # only previewing (not recording), the camera was likely
            # unplugged or switched. Try to recover automatically by
            # re-scanning for any available camera, rather than freezing
            # on the last frame or forcing the user back into Settings.
            if not self.recorder.is_recording and self._consecutive_frame_failures > 15:
                self._consecutive_frame_failures = 0
                self.recorder.close_preview()
                try:
                    used_index = self.recorder.open_camera_for_preview()
                    self.status_label.setText(f"Status: Camera reconnected (using camera {used_index}).")
                except RecorderError:
                    self.preview_timer.stop()
                    self.start_btn.setEnabled(False)
                    self.status_label.setText(
                        "Status: Camera disconnected. Reconnect a camera and click Check Location again."
                    )
            return

        self._consecutive_frame_failures = 0
        self._show_frame(frame)

    def _show_frame(self, frame):
        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        height, width, channels = rgb_frame.shape
        bytes_per_line = channels * width
        image = QImage(rgb_frame.data, width, height, bytes_per_line, QImage.Format_RGB888)
        pixmap = QPixmap.fromImage(image).scaled(
            self.preview_frame.width() - 20,
            self.preview_frame.height() - 20,
            Qt.KeepAspectRatio,
            Qt.SmoothTransformation,
        )
        self.preview_label.setPixmap(pixmap)
        self.preview_label.setText("")

    def _on_stop_recording(self):
        # stop_recording() decodes and hashes every single frame of the
        # finished video (compute_chain_from_video), then signs, encrypts,
        # and embeds the evidence package -- for anything longer than a
        # few seconds of footage this is far too slow to run directly on
        # the GUI thread (the window would freeze/"Not Responding" until
        # it finished). Run it on a background QThread instead and only
        # touch widgets again once the finished/failed signal fires back
        # on the main thread.
        self.preview_timer.stop()
        self.stop_btn.setEnabled(False)
        self.status_label.setText(
            "Status: Finalizing recording (hashing frames, signing, and "
            "encrypting evidence)... this may take a moment for longer videos."
        )

        self._stop_worker = _BackgroundTask(
            self.recorder.stop_recording,
            evidence_passphrase=self.app_state.session_password,
        )
        self._stop_worker.succeeded.connect(self._on_stop_recording_succeeded)
        self._stop_worker.failed.connect(self._on_stop_recording_failed)
        self._stop_worker.start()

    def _reset_controls_after_stop(self):
        self.check_location_btn.setEnabled(True)
        self.camera_combo.setEnabled(True)
        self.start_btn.setEnabled(False)
        self.preview_label.setPixmap(QPixmap())
        self.preview_label.setText("Camera preview will appear here")

    def _on_stop_recording_succeeded(self, summary):
        self._reset_controls_after_stop()
        self.status_label.setText(
            f"Status: Saved. {summary['frame_count']} frames hashed. "
            f"Evidence ID {summary['evidence_id'][:8]}..."
        )
        stego_note = ""
        if summary.get("stego_reference_path"):
            stego_note = (
                f"\n\nSteganographic reference frame (optional, for extra "
                f"verification):\n{summary['stego_reference_path']}"
            )
        QMessageBox.information(
            self,
            "Recording Saved",
            f"Evidence video saved to:\n{summary['video_path']}\n\n"
            f"Frames hashed: {summary['frame_count']}\n"
            f"Final chain hash: {summary['final_hash'][:32]}...{stego_note}",
        )

    def _on_stop_recording_failed(self, error_message):
        self._reset_controls_after_stop()
        self.status_label.setText("Status: Recording failed to finalize. See error for details.")
        QMessageBox.critical(self, "Recording Error", error_message)

    def shutdown(self):
        """Called by the main window on application close."""
        self.preview_timer.stop()
        stop_worker = getattr(self, "_stop_worker", None)
        if stop_worker is not None and stop_worker.isRunning():
            # Give the finalize step a moment to finish writing/embedding
            # evidence rather than yanking the thread out from under it.
            stop_worker.wait(5000)
        if self.recorder:
            if self.recorder.is_recording:
                self.recorder.cancel_recording()
            else:
                self.recorder.close_preview()

# ==========================================================================
# Originally: reports_view.py
# ==========================================================================
"""
reports_view.py
----------------
GUI screen listing all evidence records created by this installation of
Project Crygan, backed by the local SQLite database (database.py).

Supports selecting individual records (via checkboxes) to delete, or
clearing the whole history at once. Deleting here only removes database
entries -- it never touches the underlying video files on disk.
"""



# Column layout: a checkbox column first, then the actual data columns.
CHECKBOX_COLUMN = 0
EVIDENCE_ID_COLUMN = 1
COLUMN_HEADERS = ["", "Evidence ID", "Video File", "Recorded (UTC)", "Latitude", "Longitude", "Frames"]


class ReportsView(QWidget):
    def __init__(self, app_state):
        super().__init__()
        self.app_state = app_state
        self.db = EvidenceDatabase()
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(14)

        header_row = QHBoxLayout()
        heading = QLabel("Evidence Reports")
        set_class(heading, "heading")
        header_row.addWidget(heading)
        header_row.addStretch()

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh)
        set_class(refresh_btn, "primary")
        refresh_btn.setMinimumHeight(34)
        header_row.addWidget(refresh_btn)

        delete_selected_btn = QPushButton("Delete Selected")
        delete_selected_btn.setMinimumHeight(34)
        set_class(delete_selected_btn, "secondary")
        delete_selected_btn.clicked.connect(self._on_delete_selected)
        header_row.addWidget(delete_selected_btn)

        clear_all_btn = QPushButton("Clear All")
        clear_all_btn.setMinimumHeight(34)
        set_class(clear_all_btn, "secondary")
        clear_all_btn.clicked.connect(self._on_clear_all)
        header_row.addWidget(clear_all_btn)

        layout.addLayout(header_row)

        note_label = QLabel(
            "Check the box next to any record(s) to delete, then click "
            "\"Delete Selected\" -- or use \"Clear All\" to wipe the whole "
            "history. This only removes the database entry, never the "
            "underlying video file on disk."
        )
        note_label.setWordWrap(True)
        set_class(note_label, "muted")
        layout.addWidget(note_label)

        self.table = QTableWidget(0, len(COLUMN_HEADERS))
        self.table.setHorizontalHeaderLabels(COLUMN_HEADERS)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(CHECKBOX_COLUMN, QHeaderView.ResizeToContents)
        for col in range(1, len(COLUMN_HEADERS)):
            header.setSectionResizeMode(col, QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setWordWrap(True)
        layout.addWidget(self.table, stretch=1)

        self.refresh()

    def refresh(self):
        records = self.db.list_evidence_records()
        self.table.setRowCount(len(records))

        for row, record in enumerate(records):
            checkbox_item = QTableWidgetItem()
            checkbox_item.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
            checkbox_item.setCheckState(Qt.Unchecked)
            self.table.setItem(row, CHECKBOX_COLUMN, checkbox_item)

            values = [
                record["evidence_id"][:8] + "...",
                record["video_filename"],
                record["recorded_at_utc"],
                str(record["latitude"]),
                str(record["longitude"]),
                str(record["frame_count"]),
            ]
            for offset, value in enumerate(values):
                col = offset + 1
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                if col == EVIDENCE_ID_COLUMN:
                    # Stash the full (untruncated) evidence_id for deletion,
                    # since the visible text is shortened for readability.
                    item.setData(Qt.UserRole, record["evidence_id"])
                self.table.setItem(row, col, item)

    def _checked_evidence_ids(self):
        ids = []
        for row in range(self.table.rowCount()):
            checkbox_item = self.table.item(row, CHECKBOX_COLUMN)
            if checkbox_item is not None and checkbox_item.checkState() == Qt.Checked:
                id_item = self.table.item(row, EVIDENCE_ID_COLUMN)
                if id_item is not None:
                    ids.append(id_item.data(Qt.UserRole))
        return ids

    def _on_delete_selected(self):
        evidence_ids = self._checked_evidence_ids()
        if not evidence_ids:
            QMessageBox.information(
                self, "No Selection", "Check one or more rows first, then click Delete Selected."
            )
            return

        confirm = QMessageBox.question(
            self,
            "Delete Selected Records",
            f"Delete {len(evidence_ids)} evidence record(s) and their verification "
            "history from the database?\n\nThis does not delete the underlying video files.",
            QMessageBox.Yes | QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return

        for evidence_id in evidence_ids:
            self.db.delete_evidence_record(evidence_id)
        self.refresh()

    def _on_clear_all(self):
        confirm = QMessageBox.question(
            self,
            "Clear All Evidence Records",
            "Delete ALL evidence records and verification history from the database?\n\n"
            "This does not delete the underlying video files, but the record list "
            "itself cannot be recovered afterward. Continue?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return

        self.db.delete_all_evidence_records()
        self.refresh()

# ==========================================================================
# Originally: settings_view.py
# ==========================================================================
"""
settings_view.py
------------------
GUI screen for application settings:

    * Appearance -- switch between System, Light, and Dark theme, applied
      live across the whole application (see theme.py).
    * Security -- set the session password that protects/unlocks the ECC
      private key and encrypts evidence metadata.
    * Export the public key for sharing with third parties who need to
      verify evidence independently.

Camera selection lives exclusively in the Record Video screen now (see
record_view.py) -- there is no separate camera picker here, so there's
only one place that can trigger a (relatively slow) camera scan.
"""




class SettingsView(QWidget):
    def __init__(self, app_state):
        super().__init__()
        self.app_state = app_state
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(18)

        heading = QLabel("Settings")
        set_class(heading, "heading")
        layout.addWidget(heading)

        layout.addWidget(self._build_appearance_section())
        layout.addWidget(self._build_security_section())
        layout.addStretch()

        for btn in self.findChildren(QPushButton):
            if btn.property("class") is None:
                btn.setMinimumHeight(36)
                set_class(btn, "primary")

    # ------------------------------------------------------------------
    # Section builders
    # ------------------------------------------------------------------
    def _section_frame(self, title_text: str) -> QFrame:
        frame = QFrame()
        set_class(frame, "card")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(10)

        title = QLabel(title_text)
        set_class(title, "section-title")
        layout.addWidget(title)

        return frame

    def _build_appearance_section(self) -> QFrame:
        frame = self._section_frame("Appearance")
        section_layout = frame.layout()

        info_label = QLabel(
            "Choose how Project Crygan looks. \"System\" automatically follows "
            "your operating system's light/dark setting and updates live if you "
            "change it."
        )
        info_label.setWordWrap(True)
        set_class(info_label, "muted")
        section_layout.addWidget(info_label)

        theme_row = QHBoxLayout()
        self.theme_buttons = {}
        self.theme_group = QButtonGroup(self)
        self.theme_group.setExclusive(True)

        theme_manager = self.app_state.theme_manager
        current_mode = theme_manager.mode if theme_manager else SYSTEM

        for mode, label in ((SYSTEM, "System"), (LIGHT, "Light"), (DARK, "Dark")):
            btn = QPushButton(label)
            btn.setCheckable(True)
            btn.setChecked(mode == current_mode)
            btn.setMinimumHeight(32)
            set_class(btn, "segment")
            btn.clicked.connect(lambda checked, m=mode: self._on_theme_selected(m))
            self.theme_group.addButton(btn)
            self.theme_buttons[mode] = btn
            theme_row.addWidget(btn)

        theme_row.addStretch()
        section_layout.addLayout(theme_row)

        return frame

    def _build_security_section(self) -> QFrame:
        frame = self._section_frame("Security")
        security_layout = frame.layout()

        info_label = QLabel(
            "This password protects your ECC private key and encrypts evidence "
            "metadata for every recording made in this session. Your key pair "
            "persists on disk between runs -- enter the SAME password you used "
            "before to unlock it again. Only use \"Regenerate Keys\" below if "
            "you've forgotten your password or want to start fresh; it does "
            "not affect verification of videos you've already recorded.\n\n"
            "Once applied, your password is remembered (encrypted) on this "
            "device so you won't be asked for it again on the next launch. "
            "Use \"Forget Saved Password\" below if you'd rather re-enter it "
            "every time, e.g. on a shared machine."
        )
        info_label.setWordWrap(True)
        set_class(info_label, "muted")
        security_layout.addWidget(info_label)

        pass_row = QHBoxLayout()
        self.password_field = QLineEdit()
        self.password_field.setEchoMode(QLineEdit.Password)
        self.password_field.setPlaceholderText("Enter session password")

        self.toggle_password_btn = QPushButton("View")
        self.toggle_password_btn.setCheckable(True)
        self.toggle_password_btn.setMinimumWidth(64)
        self.toggle_password_btn.setStyleSheet("padding: 0 8px;")
        self.toggle_password_btn.setToolTip("Show/hide password")
        self.toggle_password_btn.clicked.connect(self._on_toggle_password_visibility)

        apply_btn = QPushButton("Apply / Unlock Keys")
        apply_btn.clicked.connect(self._on_apply_password)

        pass_row.addWidget(self.password_field, stretch=1)
        pass_row.addWidget(self.toggle_password_btn)
        pass_row.addWidget(apply_btn)
        security_layout.addLayout(pass_row)

        # If AppState already auto-unlocked the keys on startup using a
        # previously remembered password, reflect that here immediately --
        # including prefilling the (masked, since echo mode is Password)
        # password field -- instead of showing "not initialized" and
        # making the user re-enter something that already worked.
        if self.app_state.has_password():
            self.password_field.setText(self.app_state.session_password)
            initial_status = "Key status: unlocked automatically (saved password)."
        else:
            initial_status = "Key status: not initialized"

        self.key_status_label = QLabel(initial_status)
        self.key_status_label.setWordWrap(True)
        set_class(self.key_status_label, "muted")
        security_layout.addWidget(self.key_status_label)

        key_actions_row = QHBoxLayout()
        export_btn = QPushButton("Export Public Key...")
        export_btn.clicked.connect(self._on_export_public_key)
        key_actions_row.addWidget(export_btn)

        regenerate_btn = QPushButton("Regenerate Keys...")
        regenerate_btn.setMinimumHeight(36)
        set_class(regenerate_btn, "secondary")
        regenerate_btn.clicked.connect(self._on_regenerate_keys)
        key_actions_row.addWidget(regenerate_btn)

        forget_btn = QPushButton("Forget Saved Password")
        forget_btn.setMinimumHeight(36)
        set_class(forget_btn, "secondary")
        forget_btn.clicked.connect(self._on_forget_saved_password)
        key_actions_row.addWidget(forget_btn)

        key_actions_row.addStretch()
        security_layout.addLayout(key_actions_row)

        return frame

    # ------------------------------------------------------------------
    # Handlers
    # ------------------------------------------------------------------
    def _on_theme_selected(self, mode: str):
        theme_manager = self.app_state.theme_manager
        if theme_manager is None:
            return
        theme_manager.set_mode(mode)
        for m, btn in self.theme_buttons.items():
            btn.setChecked(m == mode)

    def _on_toggle_password_visibility(self, checked: bool):
        if checked:
            self.password_field.setEchoMode(QLineEdit.Normal)
            self.toggle_password_btn.setText("Hide")
        else:
            self.password_field.setEchoMode(QLineEdit.Password)
            self.toggle_password_btn.setText("View")

    def _on_apply_password(self):
        password = self.password_field.text()
        if not password:
            QMessageBox.warning(self, "Password Required", "Please enter a password.")
            return

        try:
            self.app_state.set_password(password)
            self.key_status_label.setText("Key status: unlocked and ready.")
            QMessageBox.information(
                self, "Keys Ready", "Your key pair is ready. You can now record and verify evidence."
            )
        except KeyManagerError as exc:
            self.key_status_label.setText("Key status: failed to unlock.")
            QMessageBox.critical(self, "Key Error", str(exc))

    def _on_regenerate_keys(self):
        password = self.password_field.text()
        if not password:
            QMessageBox.warning(
                self,
                "Password Required",
                "Enter the password you want to protect the NEW key pair with, then click Regenerate Keys.",
            )
            return

        confirm = QMessageBox.question(
            self,
            "Regenerate Keys?",
            "This creates a brand new key pair and overwrites the existing one.\n\n"
            "Videos you've already recorded remain fully verifiable -- verification "
            "reads the public key embedded in each video's own evidence package, not "
            "the currently active key files.\n\n"
            "Only future recordings will be signed with the new key. Continue?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return

        try:
            self.app_state.regenerate_keys(password)
            self.key_status_label.setText("Key status: new key pair generated and unlocked.")
            QMessageBox.information(self, "Keys Regenerated", "A new key pair has been generated and is ready to use.")
        except KeyManagerError as exc:
            QMessageBox.critical(self, "Key Error", str(exc))

    def _on_forget_saved_password(self):
        self.app_state.forget_saved_password()
        QMessageBox.information(
            self,
            "Saved Password Forgotten",
            "The password will no longer be remembered. You'll need to enter "
            "it again the next time you launch the app. Your current session "
            "stays unlocked until you close the app.",
        )

    def _on_export_public_key(self):
        if not self.app_state.has_password():
            QMessageBox.warning(
                self, "Keys Not Ready", "Please apply your password first to generate/unlock keys."
            )
            return

        destination, _ = QFileDialog.getSaveFileName(
            self, "Export Public Key", "crygan_public_key.pem", "PEM Files (*.pem)"
        )
        if not destination:
            return

        try:
            self.app_state.get_key_manager().export_public_key(destination)
            QMessageBox.information(self, "Exported", f"Public key exported to:\n{destination}")
        except Exception as exc:
            QMessageBox.critical(self, "Export Failed", str(exc))

# ==========================================================================
# Originally: verify_view.py
# ==========================================================================
"""
verify_view.py
---------------
GUI screen for verifying a previously recorded video's evidence package.
Lets the user pick any video file, supplies the passphrase used to
encrypt its evidence metadata, runs the full verification pipeline
(verification.py), displays results, and can generate a PDF report
(report.py).
"""




class VerifyView(QWidget):
    def __init__(self, app_state):
        super().__init__()
        self.app_state = app_state
        self.selected_video_path = None
        self.selected_stego_path = None
        self.discovered_chunk_paths = []
        self.discovered_companion_path = None
        self.resolved_evidence_id = None
        self.discovered_lsb_reference_path = None
        self.last_result = None
        self.engine = VerificationEngine()
        self.db = EvidenceDatabase()

        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(14)

        heading = QLabel("Verify Video")
        set_class(heading, "heading")
        layout.addWidget(heading)

        subheading = QLabel(
            "Select any video produced by Project Crygan to check its embedded "
            "evidence package, digital signature, and frame hash chain."
        )
        subheading.setWordWrap(True)
        set_class(subheading, "subheading")
        layout.addWidget(subheading)

        # File picker row
        file_row = QHBoxLayout()
        self.file_path_field = QLineEdit()
        self.file_path_field.setReadOnly(True)
        self.file_path_field.setPlaceholderText("No video selected")
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._on_browse)
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self._on_clear)
        file_row.addWidget(self.file_path_field, stretch=1)
        file_row.addWidget(browse_btn)
        file_row.addWidget(clear_btn)
        layout.addLayout(file_row)

        # Optional steganographic (LSB) reference frame row -- see
        # evidence_storage.py's "LSB" section. Supplying this is entirely
        # optional; verification works exactly as before without it.
        stego_row = QHBoxLayout()
        stego_label = QLabel("Steganographic reference frame (optional):")
        self.stego_path_field = QLineEdit()
        self.stego_path_field.setReadOnly(True)
        self.stego_path_field.setPlaceholderText(
            "No reference frame selected -- LSB cross-check will be skipped"
        )
        stego_browse_btn = QPushButton("Browse...")
        stego_browse_btn.clicked.connect(self._on_browse_stego_reference)
        stego_clear_btn = QPushButton("Clear")
        stego_clear_btn.clicked.connect(self._on_clear_stego_reference)
        stego_row.addWidget(stego_label)
        stego_row.addWidget(self.stego_path_field, stretch=1)
        stego_row.addWidget(stego_browse_btn)
        stego_row.addWidget(stego_clear_btn)
        layout.addLayout(stego_row)

        # Reed-Solomon erasure-coded chunk reference frames (see
        # evidence_storage.py) are discovered automatically -- there can be
        # up to ten of them per recording, so picking each one by hand
        # like the single reference frame above would be tedious. This
        # only ever matters as a FALLBACK if the video's primary embedded
        # evidence is missing/corrupted; it's silently unused otherwise.
        self.chunk_status_label = QLabel(
            "Reed-Solomon reference chunks: none discovered yet (select a video first)."
        )
        self.chunk_status_label.setWordWrap(True)
        set_class(self.chunk_status_label, "muted")
        layout.addWidget(self.chunk_status_label)

        # Companion .crygan sidecar file (see evidence_storage.py's
        # "Companion .crygan evidence file" section) -- discovered
        # automatically next to the selected video, same base name. This
        # is the recovery path that matters most when the video has left
        # the recording machine (sent to a court, another investigator,
        # etc.) and/or been transcoded, so it's surfaced clearly here
        # rather than treated as a minor technical detail.
        self.companion_status_label = QLabel(
            "Companion .crygan file: none discovered yet (select a video first)."
        )
        self.companion_status_label.setWordWrap(True)
        set_class(self.companion_status_label, "muted")
        layout.addWidget(self.companion_status_label)

        # Passphrase row
        pass_row = QHBoxLayout()
        pass_label = QLabel("Evidence passphrase:")
        self.passphrase_field = QLineEdit()
        self.passphrase_field.setEchoMode(QLineEdit.Password)
        self.passphrase_field.setPlaceholderText("Passphrase used when this video was recorded")
        pass_row.addWidget(pass_label)
        pass_row.addWidget(self.passphrase_field, stretch=1)
        layout.addLayout(pass_row)

        # Action buttons
        action_row = QHBoxLayout()
        self.verify_btn = QPushButton("Run Verification")
        self.verify_btn.clicked.connect(self._on_verify)
        self.report_btn = QPushButton("Generate PDF Report")
        self.report_btn.setEnabled(False)
        self.report_btn.clicked.connect(self._on_generate_report)
        self.open_maps_btn = QPushButton("Open in Maps")
        self.open_maps_btn.setEnabled(False)
        self.open_maps_btn.clicked.connect(self._on_open_maps)
        self.export_evidence_btn = QPushButton("Export Evidence")
        self.export_evidence_btn.setEnabled(False)
        self.export_evidence_btn.clicked.connect(self._on_export_evidence)

        for btn in (self.verify_btn, self.report_btn, self.open_maps_btn, self.export_evidence_btn):
            btn.setMinimumHeight(38)
            set_class(btn, "primary")
            action_row.addWidget(btn)
        layout.addLayout(action_row)

        # Results panel
        results_label = QLabel("Verification Results")
        set_class(results_label, "section-title")
        results_label.setStyleSheet("margin-top: 10px;")
        layout.addWidget(results_label)

        self.results_box = QTextEdit()
        self.results_box.setReadOnly(True)
        layout.addWidget(self.results_box, stretch=1)

    def _on_browse(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Video", config.VIDEOS_DIR, "Video Files (*.mp4 *.avi *.mov *.mkv)"
        )
        if path:
            self.selected_video_path = path
            self.file_path_field.setText(path)
            self.report_btn.setEnabled(False)
            self.open_maps_btn.setEnabled(False)
            self.results_box.clear()
            self._discover_chunk_paths()
            self._discover_companion_path()
            self._update_export_button_state()

    def _discover_companion_path(self):
        """
        Look for a companion .crygan sidecar file matching the selected
        video (same directory, same base name -- see evidence_storage.py's
        companion_file_path_for()). This is the recovery path that
        matters most once the video has left the recording machine, so
        finding (or not finding) one is surfaced prominently.
        """
        self.discovered_companion_path = None
        if not self.selected_video_path:
            self.companion_status_label.setText(
                "Companion .crygan file: none discovered yet (select a video first)."
            )
            return

        candidate = companion_file_path_for(self.selected_video_path)
        if os.path.exists(candidate):
            self.discovered_companion_path = candidate
            self.companion_status_label.setText(f"Companion .crygan file: found ({candidate}).")
        else:
            self.companion_status_label.setText(
                "Companion .crygan file: none found next to this video. If this video has "
                "left the recording machine without its .crygan sidecar, and its embedded "
                "evidence has also been stripped (e.g. by re-encoding), it may not be "
                "verifiable at all -- keep video and .crygan files together."
            )

    def _discover_chunk_paths(self):
        """
        Discover Reed-Solomon chunk reference PNGs (and the single LSB
        reference PNG, if present) belonging to the selected video.

        This scans every PNG in config.STEGO_REFERENCE_DIR and groups
        them by the evidence_id embedded in their own pixel content (see
        evidence_storage.py's discover_evidence_pngs()) -- NOT by
        matching the video's current filename. Filename matching breaks
        the moment a video is cropped, trimmed, renamed, or re-saved by
        an external tool; content-based grouping doesn't, because the
        chunk/reference PNGs are untouched by whatever happened to the
        video file itself.

        Resolution order:
          1. If this exact video path has a local database record (i.e.
             it hasn't been renamed/moved since recording), use its
             evidence_id directly -- the most reliable case.
          2. Otherwise, if exactly one recording's evidence is found in
             the folder at all, use it (the common case: one recording
             per stego_refs folder).
          3. Otherwise (multiple recordings' evidence present, and no
             database match to disambiguate), ask the user to pick.
        """
        self.discovered_chunk_paths = []
        self.discovered_lsb_reference_path = None
        self.resolved_evidence_id = None

        if not self.selected_video_path:
            self.chunk_status_label.setText(
                "Reed-Solomon reference chunks: none discovered yet (select a video first)."
            )
            self._update_export_button_state()
            return

        groups = discover_evidence_pngs(config.STEGO_REFERENCE_DIR)

        chosen_id = None
        db_record = self.db.get_evidence_record_by_video_path(self.selected_video_path)
        if db_record and db_record["evidence_id"] in groups:
            chosen_id = db_record["evidence_id"]
        elif len(groups) == 1:
            chosen_id = next(iter(groups))
        elif len(groups) > 1:
            chosen_id = self._prompt_choose_evidence_group(groups)

        if chosen_id and chosen_id in groups:
            group = groups[chosen_id]
            self.resolved_evidence_id = chosen_id
            self.discovered_chunk_paths = [group["chunk_paths"][i] for i in sorted(group["chunk_paths"])]
            self.discovered_lsb_reference_path = group["lsb_reference_path"]

            # If the user hasn't manually picked a different reference
            # frame, use the one we just discovered by content -- so the
            # single-frame LSB cross-check also no longer depends on
            # anyone manually browsing for it.
            if not self.selected_stego_path and self.discovered_lsb_reference_path:
                self.selected_stego_path = self.discovered_lsb_reference_path
                self.stego_path_field.setText(f"{self.discovered_lsb_reference_path} (auto-discovered)")

            if self.discovered_chunk_paths:
                self.chunk_status_label.setText(
                    f"Reed-Solomon reference chunks: found {len(self.discovered_chunk_paths)} "
                    f"for evidence_id {chosen_id} (used only if the primary embedded evidence "
                    "can't be read)."
                )
            else:
                self.chunk_status_label.setText(
                    f"Reed-Solomon reference chunks: none found for evidence_id {chosen_id} "
                    "(an LSB reference frame may still have been found, above)."
                )
        else:
            self.chunk_status_label.setText(
                "Reed-Solomon reference chunks: none found in "
                f"{config.STEGO_REFERENCE_DIR} for this recording."
            )

        self._update_export_button_state()

    def _prompt_choose_evidence_group(self, groups: dict):
        """
        When more than one recording's chunk/reference PNGs are present
        in STEGO_REFERENCE_DIR and there's no database match to
        disambiguate automatically, ask the user which one belongs to
        the video they're verifying. Returns the chosen evidence_id, or
        None if the user cancels (chunk/LSB recovery is simply skipped
        in that case -- exactly as if none had been found).
        """
        options = []
        id_by_option = {}
        for evidence_id, group in sorted(groups.items()):
            chunk_count = len(group["chunk_paths"])
            total = group["total_chunks"]
            has_ref = "yes" if group["lsb_reference_path"] else "no"
            label = f"{evidence_id}  (chunks: {chunk_count}/{total or '?'}, LSB reference: {has_ref})"
            options.append(label)
            id_by_option[label] = evidence_id

        choice, ok = QInputDialog.getItem(
            self,
            "Multiple Recordings Found",
            "More than one recording's reference PNGs were found in the stego_refs "
            "folder, and this video couldn't be automatically matched to one of them "
            "(it may have been renamed, cropped, or moved). Please choose which one "
            "belongs to this video:",
            options,
            0,
            False,
        )
        if not ok or not choice:
            return None
        return id_by_option[choice]

    def _update_export_button_state(self):
        has_any_artifact = bool(
            self.discovered_companion_path
            or self.discovered_chunk_paths
            or self.discovered_lsb_reference_path
        )
        self.export_evidence_btn.setEnabled(bool(self.selected_video_path) and has_any_artifact)

    def _on_browse_stego_reference(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Steganographic Reference Frame",
            config.STEGO_REFERENCE_DIR,
            "PNG Images (*.png)",
        )
        if path:
            self.selected_stego_path = path
            self.stego_path_field.setText(path)

    def _on_clear_stego_reference(self):
        self.selected_stego_path = None
        self.stego_path_field.clear()

    def _on_clear(self):
        """Clear the currently selected video and any verification results,
        so a new video can be selected/verified without leftover state
        (stale results, an enabled report/maps button, etc.) from the
        previous run."""
        self.selected_video_path = None
        self.selected_stego_path = None
        self.discovered_chunk_paths = []
        self.discovered_companion_path = None
        self.resolved_evidence_id = None
        self.discovered_lsb_reference_path = None
        self.last_result = None
        self.file_path_field.clear()
        self.stego_path_field.clear()
        self.passphrase_field.clear()
        self.results_box.clear()
        self.chunk_status_label.setText(
            "Reed-Solomon reference chunks: none discovered yet (select a video first)."
        )
        self.companion_status_label.setText(
            "Companion .crygan file: none discovered yet (select a video first)."
        )
        self.report_btn.setEnabled(False)
        self.open_maps_btn.setEnabled(False)
        self.export_evidence_btn.setEnabled(False)

    def _on_verify(self):
        if not self.selected_video_path:
            QMessageBox.warning(self, "No Video Selected", "Please choose a video file first.")
            return

        passphrase = self.passphrase_field.text()
        if not passphrase:
            QMessageBox.warning(self, "Passphrase Required", "Please enter the evidence passphrase.")
            return

        # VerificationEngine.verify() re-decodes and hashes every frame of
        # the video (compute_chain_from_video) to recompute the chain --
        # for anything but a very short clip this is too slow to run on
        # the GUI thread without freezing the window. Run it on a
        # background QThread and only touch widgets again once the
        # succeeded/failed signal fires back on the main thread.
        self.verify_btn.setEnabled(False)
        self.report_btn.setEnabled(False)
        self.open_maps_btn.setEnabled(False)
        self.results_box.setPlainText(
            "Verifying evidence package, signature, and frame hash chain...\n"
            "This may take a moment for longer videos."
        )

        self._verify_worker = _BackgroundTask(
            self.engine.verify,
            self.selected_video_path,
            passphrase,
            stego_reference_path=self.selected_stego_path,
            stego_chunk_paths=self.discovered_chunk_paths,
            registry_candidates=self.db.list_registry_entries(),
            companion_path=self.discovered_companion_path,
        )
        self._verify_worker.succeeded.connect(self._on_verify_succeeded)
        self._verify_worker.failed.connect(self._on_verify_failed)
        self._verify_worker.start()

    def _on_verify_succeeded(self, result):
        self.verify_btn.setEnabled(True)
        self.last_result = result
        self._render_result(result)
        self.report_btn.setEnabled(result.evidence_found and result.decryption_ok)

        gps = (result.evidence_payload or {}).get("gps", {})
        has_coordinates = gps.get("latitude") is not None and gps.get("longitude") is not None
        self.open_maps_btn.setEnabled(has_coordinates)

    def _on_verify_failed(self, error_message):
        self.verify_btn.setEnabled(True)
        self.results_box.setPlainText(f"Verification could not be completed:\n{error_message}")
        QMessageBox.critical(self, "Verification Error", error_message)

    def _render_result(self, result):
        def status(ok):
            return "PASSED" if ok else "FAILED"

        lines = []
        lines.append(f"Evidence Source        : {result.evidence_source}")
        lines.append(f"Evidence Package Found : {status(result.evidence_found)}")
        if result.companion_file_used:
            lines.append(
                "  -> Recovered from the companion .crygan evidence package, not from the "
                "video file itself (the video's own embedded copy was missing/unreadable, "
                "e.g. from transcoding)."
            )
        if result.registry_match_used:
            lines.append(
                "  -> Recovered via this machine's local registry, not from any file at all "
                "-- weaker provenance; see failure notes below."
            )
        elif result.registry_lookup_attempted:
            lines.append("  (Local registry fallback was attempted but found no sufficiently close match.)")
        lines.append(f"Metadata Decryption    : {status(result.decryption_ok)}")
        lines.append(f"Digital Signature      : {status(result.signature_ok)}")
        lines.append(f"Frame Hash Chain       : {status(result.chain_ok)}")
        if result.lsb_reference_checked:
            lsb_status = "PASSED" if result.lsb_reference_ok else "FAILED"
            lines.append(f"LSB Reference Check    : {lsb_status} (optional, extra corroboration)")
        if result.chunk_recovery_attempted:
            chunk_status = "SUCCEEDED" if result.chunk_recovery_ok else "FAILED"
            lines.append(
                f"Chunk-Based Recovery   : {chunk_status} "
                f"({result.chunk_recovery_chunks_used} of {result.chunk_recovery_chunks_available} "
                "reference chunks used -- primary embedded evidence was missing/corrupted)"
            )
        if result.merkle_checked:
            merkle_status = status(result.merkle_ok)
            lines.append(f"Merkle Frame Commitment: {merkle_status} (optional, frame-level localization)")
            if not result.merkle_ok:
                idx_str = ", ".join(str(i) for i in result.tampered_frame_indices) or "none identified"
                if result.tampered_frame_indices_truncated:
                    idx_str += ", ... (truncated)"
                lines.append(f"  -> Differing frame(s): {idx_str}")
                if result.perceptual_hashing_available:
                    transcoded_str = ", ".join(str(i) for i in result.transcoded_frame_indices) or "none"
                    altered_str = ", ".join(str(i) for i in result.content_altered_frame_indices) or "none"
                    lines.append(f"     consistent with re-encoding only: {transcoded_str}")
                    lines.append(f"     content likely changed          : {altered_str}")
        if result.timestamp_checked:
            lines.append(
                f"Trusted Timestamp (RFC 3161) : {status(result.timestamp_ok)} "
                f"(optional; TSA: {result.tsa_url or 'unknown'}, "
                f"attested time: {result.tsa_timestamp_utc or 'unknown'})"
            )
        lines.append("")
        lines.append(f"Overall Integrity      : {status(result.overall_integrity_ok)}")
        lines.append("")

        if result.evidence_payload:
            gps = result.evidence_payload.get("gps", {})
            ts = result.evidence_payload.get("timestamp", {})
            lines.append("Recording Time   : " f"{ts.get('date', 'N/A')} {ts.get('time', 'N/A')} (UTC{ts.get('utc_offset', '')})")
            accuracy = gps.get("accuracy_meters")
            accuracy_str = f"~{accuracy:.0f} m" if accuracy else "unknown (approximate)"

            # Build the "(City, Country)" suffix from only the parts that
            # are actually present -- gps.city/gps.country can be "" (e.g.
            # reverse geocoding failed at record time), and blindly
            # formatting both into "(%s, %s)" regardless left a bare
            # "(, )" sitting next to the coordinates.
            place_parts = [p for p in (gps.get("city"), gps.get("country")) if p]
            place_suffix = f" ({', '.join(place_parts)})" if place_parts else ""

            lines.append(
                "Recording Location: "
                f"{gps.get('latitude', 'N/A')}, {gps.get('longitude', 'N/A')}{place_suffix}"
            )
            lines.append(f"Location Source   : {gps.get('source', 'N/A')} (accuracy: {accuracy_str})")
            lines.append("")

        lines.append(f"Recorded frame count   : {result.recorded_frame_count}")
        lines.append(f"Recomputed frame count : {result.recomputed_frame_count}")
        lines.append(f"Recorded final hash    : {result.recorded_final_hash}")
        lines.append(f"Recomputed final hash  : {result.recomputed_final_hash}")

        if result.failure_reasons:
            lines.append("")
            lines.append("Issues detected:")
            for reason in result.failure_reasons:
                lines.append(f"  - {reason}")

        self.results_box.setPlainText("\n".join(lines))

    def _on_open_maps(self):
        if not self.last_result or not self.last_result.evidence_payload:
            return
        gps = self.last_result.evidence_payload.get("gps", {})
        latitude, longitude = gps.get("latitude"), gps.get("longitude")
        if latitude is None or longitude is None:
            return
        QDesktopServices.openUrl(QUrl(build_maps_url(latitude, longitude)))

    def _on_generate_report(self):
        if not self.last_result:
            return

        evidence_record = self.db.get_evidence_record_by_video_path(self.selected_video_path)
        evidence_id = evidence_record["evidence_id"] if evidence_record else "unknown"

        try:
            report_path = generate_report(
                evidence_id=evidence_id,
                video_filename=self.selected_video_path.split("/")[-1],
                verification_result=self.last_result,
            )
        except Exception as exc:
            QMessageBox.critical(self, "Report Generation Failed", str(exc))
            return

        if evidence_record:
            self.db.record_verification(
                evidence_id=evidence_record["evidence_id"],
                integrity_ok=self.last_result.overall_integrity_ok,
                signature_ok=self.last_result.signature_ok,
                chain_ok=self.last_result.chain_ok,
                report_path=report_path,
            )

        QMessageBox.information(self, "Report Generated", f"PDF report saved to:\n{report_path}")

    def _on_export_evidence(self):
        """
        Bundle every evidence artifact discovered for the selected video
        -- the video itself, its companion .crygan file, its LSB
        reference PNG, and its RS chunk PNGs -- into one folder named
        after this recording's evidence_id, under
        config.EVIDENCE_EXPORTS_DIR. That folder is then a single,
        self-contained unit that's easy to copy, zip, or hand to someone
        else, instead of several loose files scattered across separate
        app folders (videos/, keys/, stego_refs/).
        """
        if not self.selected_video_path:
            QMessageBox.warning(self, "No Video Selected", "Please choose a video file first.")
            return

        # Prefer the evidence_id resolved from the stego_refs scan (which
        # is content-based and therefore reliable even for a
        # renamed/cropped video); fall back to the local database record
        # for this exact video path if that's all that's available.
        evidence_id_hex = self.resolved_evidence_id
        if not evidence_id_hex:
            db_record = self.db.get_evidence_record_by_video_path(self.selected_video_path)
            if db_record:
                evidence_id_hex = db_record["evidence_id"]

        if not evidence_id_hex:
            QMessageBox.warning(
                self,
                "No Evidence ID Available",
                "Couldn't determine a unique evidence ID for this video (no database "
                "record for this exact file path, and no recognizable chunk/reference "
                "PNGs found in the stego_refs folder). There's nothing to name the "
                "export folder after.",
            )
            return

        chunk_paths_dict = {i: p for i, p in enumerate(self.discovered_chunk_paths)}

        manifest_extra = {}
        if self.last_result:
            manifest_extra["last_verification_summary"] = {
                "overall_integrity_ok": self.last_result.overall_integrity_ok,
                "evidence_source": self.last_result.evidence_source,
            }

        try:
            export_folder = export_evidence_bundle(
                destination_root=config.EVIDENCE_EXPORTS_DIR,
                evidence_id_hex=evidence_id_hex,
                video_path=self.selected_video_path,
                companion_path=self.discovered_companion_path,
                chunk_paths=chunk_paths_dict,
                lsb_reference_path=self.discovered_lsb_reference_path,
                manifest_extra=manifest_extra,
            )
        except EvidenceStorageError as exc:
            QMessageBox.critical(self, "Export Failed", str(exc))
            return

        QMessageBox.information(
            self,
            "Evidence Exported",
            f"All available evidence for this recording was copied to:\n\n{export_folder}\n\n"
            "This folder is self-contained and safe to copy, zip, or share as one unit.",
        )
