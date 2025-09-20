# Changelog

Alle nennenswerten Änderungen an diesem Projekt werden in dieser Datei dokumentiert.  
Format orientiert sich an [Keep a Changelog](https://keepachangelog.com/de/1.0.0/)  
und folgt [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

- 📝 Weitere Beispiele für Unterricht hinzufügen
- 🎨 Screenshots/GIFs der TUI im README verlinken
- 🚀 Optionale Features: rekursives Ordner-Encrypt, STDIN/STDOUT-Support

---

## [1.0.0] – 2025-09-20

### Added
- ✨ Erstveröffentlichung von **Cryptus**
- CLI: `cryptus.py` mit
  - AES-ähnlicher Stromchiffre (HMAC-SHA256 im Counter-Mode)
  - PBKDF2-HMAC-SHA256 Key Derivation (Level 1–10)
  - Roman-Zahlen-Encoding für Bytes (`0 → N`, `65 → LXV`)
  - HMAC-SHA256 Tag (Encrypt-then-MAC) für Integrität
- TUI: `cryptus_tui.py` (MC-Style mit curses)
  - Zwei-Pane-Ansicht (Input/Output)
  - Multi-Select (Space, a/A)
  - Progress-Bar bei Encrypt/Decrypt
  - Filter (Decrypt: nur `*.roman`)
  - Viewer (Text oder Hexdump)
  - Keyfile-Support (F9)
- Doku:
  - `README.md`
  - `LICENSE` (MIT)
  - `docs/crypto-primer.md` (Einführung in Kryptographie)
  - `docs/cryptus-venv-howto.md` (How-To mit venv)
- Beispiele:
  - `examples/hello.txt`

---

## [0.1.0] – 2025-09-18

### Prototype
- Erste Version des CLI-Prototyps mit Roman-Encoding
- Grundidee im Chat entwickelt, einfache Verschlüsselung als Proof of Concept
