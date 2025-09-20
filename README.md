# Cryptus — Roman Numeral Cipher (Educational)

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)]()
[![Platforms](https://img.shields.io/badge/Platforms-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey)]()

**Cryptus** ist ein kleines Lernprojekt: Dateien werden **echt** verschlüsselt (PBKDF2 + HMAC + Stream-XOR),
und der resultierende Byte-Stream wird als **römische Zahlen** ausgegeben. Ideal für Unterricht/Workshops:
greifbar, nachvollziehbar, mit Spaß-Faktor – aber **nicht für Produktionsgeheimnisse** gedacht.

> 🔒 **Sicherheitshinweis**: Educational Prototype. Für echte Sicherheit nutze auditierte Tools (z. B. age/OpenSSL/GPG).

---

## ✨ Features

- **CLI**: `cryptus.py` (encrypt/decrypt, Roman-Output, Level 1–10)
- **TUI**: `cryptus_tui.py` (zweigeteilte Oberfläche à la MC, Multi-Select, Filter, Viewer, Progress)
- **Kein Drittanbieter-Zwang**: nur Standardbibliothek (Windows-TUI braucht `windows-curses`)
- **Integritätsschutz**: HMAC-SHA256 (encrypt-then-MAC)
- **Leicht zu lesen**: Roman-Zahlen pro Byte (`0 → N`, `65 → LXV` …)

📚 Siehe **[docs/crypto-primer.md](docs/crypto-primer.md)** für eine sanfte Einführung.

---

## 📦 Installation

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .\\.venv\\Scripts\\Activate.ps1
python -m pip install --upgrade pip
# Nur Windows für TUI:
pip install -r requirements.txt
```

Ausführlich: **[docs/cryptus-venv-howto.md](docs/cryptus-venv-howto.md)**

---

## 🚀 Quickstart

### CLI

```bash
# Verschlüsseln
python cryptus.py -e -i input.bin -o output.roman --pass "geheim" -l 5 --block 64

# Entschlüsseln
python cryptus.py -d -i output.roman -o original.bin --pass "geheim"
```

### TUI (MC-Style)

```bash
python cryptus_tui.py
```
- **Tab** Pane wechseln • **Space** markieren • **F2** Modus • **F6** Start  
- **F7** Filter (*.roman) • **F8** View • **F9** Keyfile • **p** Passphrase

---

## 🧠 Wie funktioniert’s? (Kurz)

- **Passphrase → Schlüssel** via **PBKDF2-HMAC-SHA256** (Iterationen = `200k × Level`).
- **Keystream** via **HMAC-SHA256** im Counter-Mode → **XOR** mit Klartext.
- **Integrität**: **HMAC-SHA256** über Header + Ciphertext (encrypt-then-MAC).
- **Encoding**: Byte → **römische Zahl** (0..255), tokens mit Leerzeichen/Zeilenumbruch.

Header-Layout: `CRY1 | SALT(16) | NONCE(12) | LEVEL(4) | CIPHERTEXT | TAG(32)`

---

## 🧪 Beispiele

```bash
echo "Hello Cryptus!" > hello.txt
python cryptus.py -e -i hello.txt -o hello.roman --pass "x"
python cryptus.py -d -i hello.roman -o hello.dec --pass "x"
diff hello.txt hello.dec && echo OK
```

---

## 🙋 FAQ

**Produziert Cryptus starke Sicherheit?**  
Nein – es ist **Lerncode** mit realen Bausteinen, aber ohne Audit.

**Warum römische Zahlen?**  
Weil’s anschaulich ist: Man *sieht* den Cipher, versteht aber, dass Darstellung ≠ Sicherheit.

**Was, wenn der HMAC-Tag nicht passt?**  
Dann war das Passwort falsch oder die Datei beschädigt → Entschlüsselung bricht ab.

---

## 🤝 Mitmachen

PRs/Issues willkommen! Gute Einstiege:
- bessere Roman-Tokenisierung
- rekursive Ordner-Verschlüsselung
- STDIN/STDOUT-Support
- Tests, Benchmarks, Doku

---

## 📜 Lizenz

MIT – siehe [LICENSE](LICENSE).
