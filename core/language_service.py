"""
Pandora CyberSec Toolkit - Sprachdienst (Hot-Reload + Persistenz)
=====================================================================
Kapselt den geteilten Pandora-``LanguageManager`` in einem QObject und
ergänzt ihn um zwei App-spezifische Fähigkeiten:

1. Hot-Reload: Ein ``QFileSystemWatcher`` beobachtet den
   ``language_packs``-Ordner. Wird dort ein Sprachpaket hinzugefügt,
   entfernt oder geändert, lädt der Dienst alle Pakete automatisch neu
   und benachrichtigt die UI - ganz ohne Neustart der Anwendung.
2. Persistenz: Die zuletzt gewählte Sprache wird per ``QSettings``
   gespeichert und beim nächsten Start automatisch wiederhergestellt.
"""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import QObject, pyqtSignal, QFileSystemWatcher, QSettings

from language_plugin.language_manager import LanguageManager, LANGUAGE_PACKS_DIR


class LanguageService(QObject):
    """Zentrale Sprachverwaltung mit Hot-Reload und Live-Umschaltung."""

    # Wird gefeuert, sobald sich die aktive Sprache ändert (Code als Arg)
    language_changed = pyqtSignal(str)
    # Wird gefeuert, sobald Sprachpakete neu von der Platte geladen wurden
    packs_reloaded = pyqtSignal()

    def __init__(
        self,
        parent: QObject | None = None,
        packs_dir: str | None = None,
        default_language: str = "de",
    ):
        super().__init__(parent)
        self.manager = LanguageManager(
            packs_dir=packs_dir or LANGUAGE_PACKS_DIR,
            default_language=default_language,
        )
        self.settings = QSettings("Pandora", "Pandora CyberSec Toolkit")

        saved_code = self.settings.value("language/code", default_language)
        if isinstance(saved_code, str) and saved_code in self.manager.available_languages():
            self.manager.set_language(saved_code)

        self.watcher = QFileSystemWatcher(self)
        self._register_watch_paths()
        self.watcher.directoryChanged.connect(self._on_packs_changed)
        self.watcher.fileChanged.connect(self._on_packs_changed)

    # ------------------------------------------------------- Hot-Reload
    def _register_watch_paths(self) -> None:
        base = Path(self.manager.packs_dir)
        paths: list[str] = [str(base)]
        if base.is_dir():
            for entry in base.iterdir():
                if entry.is_dir():
                    paths.append(str(entry))
                elif entry.suffix == ".json":
                    paths.append(str(entry))

        existing = [p for p in paths if Path(p).exists()]
        if not existing:
            return
        already_watched = set(self.watcher.directories()) | set(self.watcher.files())
        new_paths = [p for p in existing if p not in already_watched]
        if new_paths:
            self.watcher.addPaths(new_paths)

    def _on_packs_changed(self, _path: str) -> None:
        current = self.manager.current_language
        self.manager.reload_available()

        available = self.manager.available_languages()
        if current not in available:
            fallback = self.manager.default_language
            if fallback not in available and available:
                fallback = next(iter(available))
            if fallback in available:
                self.manager.set_language(fallback)

        self._register_watch_paths()
        self.packs_reloaded.emit()
        self.language_changed.emit(self.manager.current_language)

    def reload_now(self) -> None:
        """Manuelles, sofortiges Neuladen aller Sprachpakete (z. B. über
        den Button „Sprachpakete neu laden“ im Einstellungen-Dialog)."""
        self._on_packs_changed(str(self.manager.packs_dir))

    # -------------------------------------------------------- Sprachen
    def available_languages(self) -> dict:
        return self.manager.available_languages()

    def current_language(self) -> str:
        return self.manager.current_language

    def set_language(self, code: str) -> bool:
        """Wechselt die aktive Sprache live und speichert die Wahl
        dauerhaft über Neustarts hinweg."""
        if self.manager.set_language(code):
            self.settings.setValue("language/code", code)
            self.settings.sync()
            self.language_changed.emit(code)
            return True
        return False

    # ------------------------------------------------------- Übersetzen
    def tr(self, key: str, **kwargs) -> str:
        return self.manager.tr(key, **kwargs)
