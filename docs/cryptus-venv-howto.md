# Cryptus: Einrichtung mit Python-`venv` (macOS, Linux, Windows)

**Ziel:** Dieses How‑To zeigt dir Schritt für Schritt, wie du für `cryptus.py` (CLI) und `cryptus_tui.py` (TUI im Terminal) eine saubere Python‑Umgebung erstellst und die nötigen Pakete installierst. Perfekt zum Copy‑&‑Paste in MarsEdit.

> **Kurzfazit:**  
> - **macOS/Linux:** Keine zusätzlichen Pakete erforderlich.  
> - **Windows:** Für die TUI brauchst du **`windows-curses`**. Die CLI (`cryptus.py`) läuft ohne Extra-Pakete.

---

## 1) Voraussetzungen prüfen

### macOS / Linux (Bash/Zsh)
```bash
python3 --version
# Erwartet: Python 3.8+
```

### Windows (PowerShell)
```powershell
py -3 --version
# oder
python --version
```

> Wenn kein Python installiert ist: Nutze den offiziellen Installer von [python.org](https://www.python.org/) (Windows: Häkchen bei „Add Python to PATH“ setzen).

---

## 2) Projektordner anlegen

Lege dir einen neuen Ordner an (z. B. `cryptus`) und wechsle hinein.

### macOS / Linux
```bash
mkdir -p ~/Projects/cryptus && cd ~/Projects/cryptus
```

### Windows (PowerShell)
```powershell
New-Item -ItemType Directory -Path $HOME\\Projects\\cryptus -Force | Out-Null
Set-Location $HOME\\Projects\\cryptus
```

Kopiere die beiden Dateien **`cryptus.py`** und **`cryptus_tui.py`** in diesen Ordner (z. B. aus dem Chat).

---

## 3) Virtuelle Umgebung (venv) erstellen

### macOS / Linux
```bash
python3 -m venv .venv
```

### Windows (PowerShell)
```powershell
py -3 -m venv .venv
# falls 'py' nicht existiert:
# python -m venv .venv
```

---

## 4) venv aktivieren

### macOS / Linux (Bash/Zsh)
```bash
source .venv/bin/activate
# Prompt sollte jetzt etwas wie (.venv) anzeigen
```

**Fish-Shell:**
```bash
source .venv/bin/activate.fish
```

### Windows (PowerShell)
```powershell
.\.venv\Scripts\Activate.ps1
# Hinweis: Wenn eine Ausführungsrichtlinien-Warnung kommt:
# Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

> **Deaktivieren** (alle Systeme): `deactivate`

---

## 5) Pip aktualisieren

```bash
python -m pip install --upgrade pip
```

---

## 6) Abhängigkeiten installieren

### Pflicht
- **CLI (`cryptus.py`)**: *keine Drittanbieter-Pakete erforderlich* (nur Python-Standardbibliothek).
- **TUI (`cryptus_tui.py`)**:
  - **macOS/Linux:** nutzt `curses`, bereits im System-Python enthalten.
  - **Windows:** installiere `windows-curses`:

#### Windows (nur für TUI)
```powershell
pip install windows-curses
```

*(Optional)* Du kannst dir eine `requirements.txt` ablegen, z. B. für Windows-Nutzer:

```txt
# requirements.txt (nur nötig für Windows-TUI)
windows-curses>=2.3.0
```

Installation dann mit:
```bash
pip install -r requirements.txt
```

---

## 7) Funktionstest (Schnellstart)

Lege eine kleine Testdatei an und verschlüssele/entschlüssele sie.

### 7.1 Testdatei erzeugen
```bash
echo \"Hello Cryptus! 12345\" > hello.txt
```

### 7.2 Verschlüsseln (CLI)
```bash
python cryptus.py -e -i hello.txt -o hello.roman --pass \"meinpass\" -l 5 --block 64
```

- Ergebnis: `hello.roman` (UTF‑8‑Text, römische Zahlentokens, Zeilenbreite 64)

### 7.3 Entschlüsseln (CLI)
```bash
python cryptus.py -d -i hello.roman -o hello.dec --pass \"meinpass\"
```

### 7.4 Prüfen (Inhalt / Hash)

**macOS/Linux:**
```bash
diff hello.txt hello.dec && echo \"OK: Dateien sind identisch\"
# oder
shasum -a 256 hello.txt hello.dec
```

**Windows (PowerShell):**
```powershell
fc hello.txt hello.dec
# oder
Get-FileHash hello.txt -Algorithm SHA256
Get-FileHash hello.dec -Algorithm SHA256
```

---

## 8) TUI starten (MC‑Style Commander)

```bash
python cryptus_tui.py
```

**Steuerung (Kurzüberblick):**  
- **Tab** – Pane wechseln (links: Input-Datei, rechts: Output-Ordner)  
- **↑/↓**/**j/k** – Auswahl bewegen  
- **←/Backspace** – Ordner hoch  
- **Enter** – Ordner öffnen / Datei fokussieren  
- **Space** – Datei markieren (Multi-Select)  
- **a / A** – alle markieren / Auswahl leeren  
- **F2** – Modus: Encrypt ↔ Decrypt  
- **F3** – Level 1–10  
- **F4** – Blockbreite (Encrypt; `0` = kein Umbruch)  
- **F5** – Ausgabename (Single-File)  
- **p** – Passphrase eingeben (maskiert)  
- **F7** – Filter (Decrypt: nur `*.roman`)  
- **F8** – Datei ansehen (Text/Hex)  
- **F9** – Keyfile-Pfad setzen (optional; wird mit Passphrase kombiniert)  
- **F6** – Start (auf Auswahl oder aktuelle Datei)  
- **q** – Quit

---

## 9) Typische Ordnerstruktur

```text
cryptus/
├─ .venv/               # virtuelle Umgebung
├─ cryptus.py           # CLI (Roman-cipher)
├─ cryptus_tui.py       # TUI (curses)
└─ hello.txt            # deine Testdateien etc.
```

*(Optional)*: `requirements.txt` (nur Windows für TUI).

---

## 10) Troubleshooting

- **TUI startet nicht unter Windows / „_curses not found“**  
  → `pip install windows-curses` in der aktiven venv ausführen.  
  → Prüfen: `where python` (PowerShell) / `Get-Command python` (zeigt Pfad).

- **„python: command not found“**  
  → Unter macOS/Linux ggf. mit `python3` statt `python` aufrufen.  
  → Unter Windows ggf. `py -3` nutzen oder PATH prüfen.

- **Unicode/Icons sehen komisch aus**  
  → Terminal sollte UTF‑8 nutzen (macOS Terminal/iTerm2 standardmäßig). Unter Windows neue Windows Terminal verwenden und die Schriftart auf eine Unicode‑fähige Schrift setzen.

- **Sicherheit**  
  `cryptus.py` ist ein **Lern-/Prototyp‑Tool** (PBKDF2 + HMAC + Stream‑XOR). Für hochsensible Daten nutze etablierte, auditierte Tools (z. B. age, OpenSSL, GPG).

---

## 11) (Optional) kleine Quality‑of‑Life‑Helfer

### Bash/Zsh Alias (macOS/Linux)
```bash
echo \"alias cryptus='python $(pwd)/cryptus.py'\" >> ~/.zshrc
source ~/.zshrc
# dann:
cryptus -e -i hello.txt -o hello.roman --pass 'x'
```

### PowerShell‑Alias (Windows)
```powershell
Add-Content $PROFILE \"Set-Alias cryptus (Join-Path (Get-Location) 'cryptus.py')\"
. $PROFILE
# dann:
python cryptus -e -i hello.txt -o hello.roman --pass 'x'
```

---

**Viel Spaß mit Cryptus!**  
Fragen oder Wunsch‑Features (Rekursives Verschlüsseln von Ordnern, Roman‑Header‑Viewer, STDIN/STDOUT‑Modus, PyInstaller‑Binary)? — Sag Bescheid 🙂
