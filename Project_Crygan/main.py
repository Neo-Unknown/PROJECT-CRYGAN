"""
main.py
-------
Entry point for Project Crygan.

Run with:
    python main.py

This project is organized into five files:
    * main.py          -- this file: application bootstrap only
    * config.py         -- shared constants/paths (unchanged from the
                            original config.py; a real standalone module
                            so nothing is duplicated between the two
                            files below)
    * project_UI.py     -- all GUI screens + supporting app/session logic
                            (formerly: theme, database, remember,
                            location, recorder, app_state, report,
                            main_window, record_view, reports_view,
                            settings_view, verify_view)
    * crypto_core.py    -- all cryptography, key management, hashing, and
                            verification logic (formerly: crypto_utils,
                            keys, hash_chain, verification -- see that
                            file's docstring for why it isn't literally
                            named cryptography.py)
    * evidence_storage.py -- evidence package storage/recovery: in-file
                            embedding (ISO-BMFF uuid box), companion
                            .crygan sidecar evidence packages, LSB
                            reference frames, Reed-Solomon chunk
                            recovery, and payload validation. Renamed
                            from the original "steganography.py" --
                            pixel-domain LSB embedding is now only one
                            of several things this module does, so the
                            old name no longer described it accurately.

Third-party dependencies required to run this app:
    PySide6, cryptography, opencv-python (cv2), requests, reportlab
Optional (enable extra features if installed):
    winsdk     -- precise Windows Location Services (location.py)
    pygrabber  -- DirectShow camera names on Windows (recorder.py)
See requirements.txt.
"""

import logging
import sys

from PySide6.QtWidgets import QApplication

import config
from project_UI import ThemeManager, MainWindow



def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    app = QApplication(sys.argv)
    app.setApplicationName(config.APP_NAME)
    app.setOrganizationName(config.ORGANIZATION_NAME)

    # Installs the initial stylesheet (system/light/dark, per the user's
    # saved preference) before any window is shown.
    theme_manager = ThemeManager(app)

    window = MainWindow(theme_manager)
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
