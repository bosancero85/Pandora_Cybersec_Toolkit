"""
Pandora CyberSec Toolkit - Einstellungen-Dialog
===================================================
Eigenständiger Dialog für App-Einstellungen. Aktuell: Sprachauswahl
(10 Sprachen, Flagge + Name) mit sofortiger Live-Umschaltung der
gesamten Oberfläche sowie manuellem Hot-Reload-Trigger für neu
hinzugefügte oder geänderte Sprachpakete.
"""

from __future__ import annotations

from PyQt6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QComboBox,
    QPushButton,
    QGroupBox,
)

from core.language_service import LanguageService


class SettingsDialog(QDialog):
    """Einstellungen-Dialog mit eigener UI, aktuell fokussiert auf
    Sprachauswahl. Wechselt die Sprache sofort bei Auswahl (Live-Preview),
    ohne dass der Dialog erst geschlossen werden muss."""

    def __init__(self, language_service: LanguageService, parent=None):
        super().__init__(parent)
        self.lang = language_service
        self.setMinimumSize(420, 260)
        self._build_ui()
        self.retranslate_ui()

        self.lang.language_changed.connect(self._on_language_changed_externally)
        self.lang.packs_reloaded.connect(self._reload_language_combo)

    # ------------------------------------------------------------- UI
    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 20, 20, 20)
        outer.setSpacing(14)

        self.title_label = QLabel()
        self.title_label.setObjectName("TitleLabel")
        outer.addWidget(self.title_label)

        self.lang_group = QGroupBox()
        group_layout = QVBoxLayout(self.lang_group)
        group_layout.setSpacing(10)

        self.lang_label = QLabel()
        group_layout.addWidget(self.lang_label)

        self.language_combo = QComboBox()
        self._reload_language_combo()
        self.language_combo.currentIndexChanged.connect(self._on_language_selected)
        group_layout.addWidget(self.language_combo)

        self.hotreload_hint_label = QLabel()
        self.hotreload_hint_label.setWordWrap(True)
        group_layout.addWidget(self.hotreload_hint_label)

        self.reload_button = QPushButton()
        self.reload_button.clicked.connect(self.lang.reload_now)
        group_layout.addWidget(self.reload_button)

        outer.addWidget(self.lang_group)
        outer.addStretch(1)

        button_row = QHBoxLayout()
        button_row.addStretch(1)
        self.close_button = QPushButton()
        self.close_button.clicked.connect(self.accept)
        button_row.addWidget(self.close_button)
        outer.addLayout(button_row)

    # -------------------------------------------------------- language
    def _reload_language_combo(self) -> None:
        """Baut die Sprachliste (Flagge + Name) neu auf, sortiert nach
        Anzeigename, und selektiert die aktuell aktive Sprache."""
        current_code = self.lang.current_language()
        self.language_combo.blockSignals(True)
        self.language_combo.clear()

        languages = self.lang.available_languages()
        for code, meta in sorted(languages.items(), key=lambda kv: kv[1]["name"].lower()):
            flag = meta.get("flag", "")
            name = meta.get("name", code.upper())
            label = f"{flag}  {name}".strip()
            self.language_combo.addItem(label, code)

        index = self.language_combo.findData(current_code)
        if index >= 0:
            self.language_combo.setCurrentIndex(index)
        self.language_combo.blockSignals(False)

    def _on_language_selected(self, _index: int) -> None:
        code = self.language_combo.currentData()
        if code and code != self.lang.current_language():
            self.lang.set_language(code)

    def _on_language_changed_externally(self, _code: str) -> None:
        # z. B. durch Hot-Reload ausgelöster Sprachwechsel (Fallback) -
        # Combobox-Auswahl synchron halten und Dialogtexte neu übersetzen.
        self._reload_language_combo()
        self.retranslate_ui()

    # ------------------------------------------------------ Übersetzung
    def retranslate_ui(self) -> None:
        tr = self.lang.tr
        self.setWindowTitle(tr("settings.window_title"))
        self.title_label.setText(tr("settings.window_title"))
        self.lang_group.setTitle(tr("settings.language_section"))
        self.lang_label.setText(tr("settings.language_label"))
        self.hotreload_hint_label.setText(tr("settings.hotreload_hint"))
        self.reload_button.setText(tr("button.reload_languages"))
        self.close_button.setText(tr("button.close"))
