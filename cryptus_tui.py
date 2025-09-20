#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import curses
import os
import sys
import time
from pathlib import Path

"""
cryptus_tui.py — Two‑pane curses UI (MC-style) for cryptus.py

NEW FEATURES
- File filter (Decrypt mode shows only *.roman when enabled) — F7
- Multi-select with Space, Select All 'a', Clear All 'A'
- Progress bar for operations
- Viewer (F8): text preview or hex dump
- Keyfile support (F9): combine with passphrase

Controls
  Tab         Switch pane (Left = INPUT, Right = OUTPUT DIR)
  ↑/↓ or j/k  Move selection
  ←/Backsp    Go up (..)
  Enter       Open directory / focus file
  Space       Toggle select on file (left pane)
  a / A       Select all (files only) / Clear selection (left pane)
  F2          Toggle mode (Encrypt/Decrypt)
  F3          Set Level (1–10)
  F4          Set Block width (wrap, encrypt only; 0 = no wrap)
  F5          Set Output filename (optional, for single-file ops)
  p           Enter Passphrase (masked)
  F7          Toggle filter (Decrypt: *.roman only)
  F8          View selected file (left pane)
  F9          Set Keyfile path (reads bytes; optional)
  F6          Run (encrypt/decrypt) on current or selected files
  q           Quit
"""

# ---- import cryptus primitives ----
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
try:
    import cryptus  # must be alongside this file
except Exception as e:
    print("Fehler: cryptus.py nicht gefunden oder importierbar. Lege diese Datei neben cryptus_tui.py.")
    print(e)
    sys.exit(1)

# ---- helpers ----

def list_dir(path: Path, mode: str, filter_enabled: bool):
    try:
        entries = []
        if path.parent != path:
            entries.append(("..", True))
        with os.scandir(path) as it:
            for e in it:
                is_dir = e.is_dir()
                name = e.name + ("/" if is_dir else "")
                if not is_dir and filter_enabled and mode == "Decrypt":
                    if not e.name.lower().endswith(".roman"):
                        continue
                entries.append((name, is_dir))
        entries.sort(key=lambda x: (not x[1], x[0].lower()))
        return entries
    except Exception as e:
        return [("<<Zugriff verweigert: {}>>".format(e), False)]

def clamp(n, a, b):
    return max(a, min(b, n))

def prompt_line(stdscr, prompt, initial="", mask=False):
    curses.curs_set(1)
    h, w = stdscr.getmaxyx()
    width = min(max(len(prompt) + 40, 40), w - 4)
    win = curses.newwin(3, width, h-4, (w - width)//2)
    win.box()
    win.addstr(0, 2, " Eingabe ")
    s = list(initial)
    pos = len(s)
    while True:
        win.addstr(1, 2, (prompt + " ").ljust(len(prompt)+1))
        disp = "".join("*" if mask and ch != " " else ch for ch in s)
        visible = disp[:width - len(prompt) - 5]
        win.addstr(1, len(prompt) + 3, " " * (width - len(prompt) - 5))
        win.addstr(1, len(prompt) + 3, visible)
        win.move(1, len(prompt) + 3 + min(pos, len(visible)))
        win.refresh()
        ch = stdscr.getch()
        if ch in (10, 13):  # Enter
            curses.curs_set(0); return "".join(s)
        elif ch in (27,):   # Esc
            curses.curs_set(0); return None
        elif ch in (curses.KEY_BACKSPACE, 127, 8):
            if pos > 0: pos -= 1; s.pop(pos)
        elif ch == curses.KEY_LEFT:
            pos = max(0, pos-1)
        elif ch == curses.KEY_RIGHT:
            pos = min(len(s), pos+1)
        elif 32 <= ch <= 126:
            s.insert(pos, chr(ch)); pos += 1

def draw_status(stdscr, title, info, status):
    h, w = stdscr.getmaxyx()
    stdscr.attron(curses.A_REVERSE)
    stdscr.addstr(0, 0, title.ljust(w-1))
    stdscr.attroff(curses.A_REVERSE)
    stdscr.addnstr(h-2, 0, info, w-1)
    stdscr.attron(curses.A_REVERSE)
    stdscr.addstr(h-1, 0, status.ljust(w-1))
    stdscr.attroff(curses.A_REVERSE)

def draw_progress(stdscr, fraction, note=""):
    h, w = stdscr.getmaxyx()
    bar_w = max(10, w - 20)
    filled = int(bar_w * fraction)
    bar = "[" + "#" * filled + "-" * (bar_w - filled) + "]"
    stdscr.addnstr(h-3, 2, f"{bar} {int(fraction*100)}% {note}", w-4)
    stdscr.refresh()

def draw_pane(win, path: Path, items, sel, focused, header, selected_set):
    win.erase()
    h, w = win.getmaxyx()
    win.box()
    win.addnstr(0, 2, f" {header}: {str(path)} ", w-4)
    top = 1
    view_h = h - 2
    start = max(0, sel - view_h + 1) if sel >= view_h else 0
    for idx in range(start, min(len(items), start + view_h)):
        name, is_dir = items[idx]
        marker = "● " if (not is_dir and (path / name).resolve() in selected_set) else "  "
        icon = "📁 " if is_dir else "📄 "
        line = marker + icon + name
        attr = curses.A_REVERSE | (curses.A_BOLD if focused else 0) if idx == sel else 0
        win.addnstr(top + idx - start, 1, line, w-2, attr)
    win.refresh()

def view_file(stdscr, path: Path):
    try:
        data = path.read_bytes()
    except Exception as e:
        return
    # Try text
    try:
        text = data.decode("utf-8")
        content = text
    except UnicodeDecodeError:
        # Hex dump first 4096 bytes
        chunk = data[:4096]
        lines = []
        for i in range(0, len(chunk), 16):
            seg = chunk[i:i+16]
            hexs = " ".join(f"{b:02X}" for b in seg)
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in seg)
            lines.append(f"{i:08X}  {hexs:<47}  {asc}")
        content = "\n".join(lines)
    h, w = stdscr.getmaxyx()
    win_h = min(h-4, max(10, h-6))
    win_w = min(w-4, max(40, w-6))
    win = curses.newwin(win_h, win_w, 2, (w - win_w)//2)
    win.box()
    win.addnstr(0, 2, f" View: {path.name} ", win_w-4)
    # Scrollable text
    lines = content.splitlines() or ["(leer)"]
    off = 0
    while True:
        for y in range(1, win_h-1):
            idx = off + y - 1
            win.move(y, 1)
            win.clrtoeol()
            if 0 <= idx < len(lines):
                win.addnstr(y, 1, lines[idx], win_w-2)
        win.refresh()
        ch = stdscr.getch()
        if ch in (27, ord('q')):  # Esc/q to close
            break
        elif ch in (curses.KEY_UP, ord('k')):
            off = max(0, off - 1)
        elif ch in (curses.KEY_DOWN, ord('j')):
            off = min(max(0, len(lines) - (win_h-2)), off + 1)
        elif ch in (curses.KEY_PPAGE,):
            off = max(0, off - (win_h-2))
        elif ch in (curses.KEY_NPAGE,):
            off = min(max(0, len(lines) - (win_h-2)), off + (win_h-2))

def get_auth_bytes(passphrase, keyfile_path):
    auth = b""
    if passphrase: auth += passphrase.encode("utf-8")
    if keyfile_path:
        try:
            auth += Path(keyfile_path).read_bytes()
        except Exception:
            pass
    return auth if auth else None

# For progress-friendly encryption we replicate the keystream loop with an explicit counter.
import hashlib, hmac, os

def hmac_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    ctr_bytes = counter.to_bytes(8, "big")
    return hmac.new(key, nonce + ctr_bytes, hashlib.sha256).digest()

def encrypt_with_progress(data: bytes, pass_bytes: bytes, level: int, progress_cb):
    # reproduce cryptus internals
    SALT_LEN, NONCE_LEN = 16, 12
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    enc_key, mac_key = cryptus.derive_keys(pass_bytes, salt, level)
    header = b"CRY1" + salt + nonce + int(level).to_bytes(4, "big")
    # stream XOR in chunks
    CHUNK = 1 << 16  # 64 KiB
    out = bytearray()
    counter = 0
    total = len(data)
    done = 0
    while done < total:
        n = min(CHUNK, total - done)
        # Generate enough stream blocks
        need = n
        ks = bytearray()
        while len(ks) < need:
            ks.extend(hmac_block(enc_key, nonce, counter))
            counter += 1
        block = bytes(ks[:n])
        out.extend(bytes(a ^ b for a, b in zip(data[done:done+n], block)))
        done += n
        if progress_cb:
            progress_cb(done / total if total else 1.0)
    ciphertext = bytes(out)
    tag = hmac.new(mac_key, header + ciphertext, hashlib.sha256).digest()
    return header + ciphertext + tag

def decrypt_with_progress(blob: bytes, pass_bytes: bytes, progress_cb):
    # exact same as cryptus.decrypt_bytes but allow progress on XOR stage
    if len(blob) < 4 + 16 + 12 + 4 + 32:
        raise ValueError("Ciphertext zu kurz/korrupt.")
    magic = blob[:4]
    if magic != b"CRY1":
        raise ValueError("Bad magic header.")
    salt = blob[4:20]
    nonce = blob[20:32]
    level = int.from_bytes(blob[32:36], "big")
    tag = blob[-32:]
    ciphertext = blob[36:-32]
    enc_key, mac_key = cryptus.derive_keys(pass_bytes, salt, level)
    header = b"CRY1" + salt + nonce + level.to_bytes(4, "big")
    calc_tag = hmac.new(mac_key, header + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, calc_tag):
        raise ValueError("Authentication failed (Passwort falsch oder Datei beschädigt).")
    # XOR with progress
    CHUNK = 1 << 16
    total = len(ciphertext)
    done = 0
    out = bytearray()
    counter = 0
    while done < total:
        n = min(CHUNK, total - done)
        # generate stream
        need = n
        ks = bytearray()
        while len(ks) < need:
            ks.extend(hmac_block(enc_key, nonce, counter))
            counter += 1
        block = bytes(ks[:n])
        out.extend(bytes(a ^ b for a, b in zip(ciphertext[done:done+n], block)))
        done += n
        if progress_cb:
            progress_cb(done / total if total else 1.0)
    return bytes(out)

def main(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(False)
    stdscr.keypad(True)

    left_path = Path.cwd()
    right_path = Path.cwd()

    mode = "Encrypt"
    level = 4
    block = 80
    output_name = ""
    filter_enabled = True
    password = None
    keyfile = ""
    selection = set()  # set[Path]

    left_items = list_dir(left_path, mode, filter_enabled)
    right_items = list_dir(right_path, mode, filter_enabled)
    left_sel = 0
    right_sel = 0
    focus_left = True

    status = "Tab Pane | F2 Mode | F3 Level | F4 Block | F5 Output | p Pass | F7 Filter | F8 View | F9 Keyfile | Space mark | a/A all/none | F6 Run | q Quit"

    def info_line():
        return (f"Mode:{mode}  Level:{level}  Block:{block}  Filter:{'ON' if (filter_enabled and mode=='Decrypt') else 'OFF'}  "
                f"Output:{output_name or '(auto)'}  Pass:{'●●●●' if (password or keyfile) else '(none)'}  Keyfile:{Path(keyfile).name if keyfile else '(none)'}")

    while True:
        h, w = stdscr.getmaxyx()
        mid = w // 2
        left_win = curses.newwin(h-3, mid, 1, 0)
        right_win = curses.newwin(h-3, w - mid, 1, mid)

        draw_pane(left_win, left_path, left_items, left_sel, focus_left, "INPUT", selection)
        draw_pane(right_win, right_path, right_items, right_sel, not focus_left, "OUTPUT DIR", set())

        draw_status(stdscr, " cryptus_tui — Commander für cryptus.py ", info_line(), status)
        stdscr.refresh()

        ch = stdscr.getch()
        if ch in (ord('q'), 27):
            break
        elif ch == 9:  # Tab
            focus_left = not focus_left
        elif ch in (curses.KEY_UP, ord('k')):
            if focus_left:
                left_sel = clamp(left_sel - 1, 0, len(left_items)-1)
            else:
                right_sel = clamp(right_sel - 1, 0, len(right_items)-1)
        elif ch in (curses.KEY_DOWN, ord('j')):
            if focus_left:
                left_sel = clamp(left_sel + 1, 0, len(left_items)-1)
            else:
                right_sel = clamp(right_sel + 1, 0, len(right_items)-1)
        elif ch in (curses.KEY_BACKSPACE, 127, curses.KEY_LEFT, ord('h')):
            if focus_left:
                left_path = left_path.parent
                left_items = list_dir(left_path, mode, filter_enabled)
                left_sel = 0
                selection.clear()
            else:
                right_path = right_path.parent
                right_items = list_dir(right_path, mode, filter_enabled)
                right_sel = 0
        elif ch in (10, 13):  # Enter
            if focus_left and left_items:
                name, is_dir = left_items[left_sel]
                target = (left_path / ("" if name == ".." else name)).resolve()
                if name == "..":
                    left_path = left_path.parent
                    left_items = list_dir(left_path, mode, filter_enabled)
                    left_sel = 0
                    selection.clear()
                elif is_dir:
                    left_path = target
                    left_items = list_dir(left_path, mode, filter_enabled)
                    left_sel = 0
                    selection.clear()
            elif (not focus_left) and right_items:
                name, is_dir = right_items[right_sel]
                target = (right_path / ("" if name == ".." else name)).resolve()
                if name == "..":
                    right_path = right_path.parent
                    right_items = list_dir(right_path, mode, filter_enabled)
                    right_sel = 0
                elif is_dir:
                    right_path = target
                    right_items = list_dir(right_path, mode, filter_enabled)
                    right_sel = 0
        elif ch == ord(' '):
            if focus_left and left_items:
                name, is_dir = left_items[left_sel]
                if not is_dir and name != "..":
                    p = (left_path / name).resolve()
                    if p in selection:
                        selection.remove(p)
                    else:
                        selection.add(p)
        elif ch in (ord('a'),):
            # select all files in current left dir
            for name, is_dir in left_items:
                if (not is_dir) and name != "..":
                    selection.add((left_path / name).resolve())
        elif ch in (ord('A'),):
            selection.clear()
        elif ch == curses.KEY_F2:
            mode = "Decrypt" if mode == "Encrypt" else "Encrypt"
            left_items = list_dir(left_path, mode, filter_enabled)
            left_sel = 0; selection.clear()
            status = f"Mode: {mode}"
            if mode == "Decrypt": block = 0
        elif ch == curses.KEY_F3:
            val = prompt_line(stdscr, "Level (1–10):", str(level))
            if val is not None and val.isdigit():
                level = clamp(int(val), 1, 10)
                status = f"Level = {level}"
        elif ch == curses.KEY_F4:
            val = prompt_line(stdscr, "Blockbreite (0 = keine Umbrüche):", str(block))
            if val is not None and val.isdigit():
                block = clamp(int(val), 0, 500)
                status = f"Block = {block}"
        elif ch == curses.KEY_F5:
            val = prompt_line(stdscr, "Output-Dateiname:", output_name or "")
            if val is not None:
                output_name = val.strip()
                status = f"Output = {output_name or '(auto)'}"
        elif ch in (ord('p'), ord('P')):
            val = prompt_line(stdscr, "Passphrase:", "", mask=True)
            if val is not None:
                password = val
                status = "Passphrase gesetzt"
        elif ch == curses.KEY_F7:
            filter_enabled = not filter_enabled
            left_items = list_dir(left_path, mode, filter_enabled)
            left_sel = 0; selection.clear()
            status = f"Filter {'aktiv' if filter_enabled else 'aus'}"
        elif ch == curses.KEY_F8:
            if focus_left and left_items:
                name, is_dir = left_items[left_sel]
                if not is_dir and name != "..":
                    view_file(stdscr, (left_path / name).resolve())
        elif ch == curses.KEY_F9:
            val = prompt_line(stdscr, "Keyfile-Pfad:", keyfile or "")
            if val is not None:
                keyfile = val.strip()
                status = f"Keyfile gesetzt: {Path(keyfile).name if keyfile else '(none)'}"
        elif ch == curses.KEY_F6:
            # run operation on selection or current file
            targets = list(selection)
            if not targets:
                if left_items:
                    name, is_dir = left_items[left_sel]
                    if not is_dir and name != "..":
                        targets = [(left_path / name).resolve()]
            if not targets:
                status = "Nichts ausgewählt."
                continue
            auth = get_auth_bytes(password, keyfile)
            if not auth:
                status = "Passphrase oder Keyfile fehlt (p / F9)."
                continue
            # For batch, output_name only applies for single-file ops
            for idx, in_path in enumerate(targets, 1):
                # progress UI header
                status = f"[{idx}/{len(targets)}] {('Encrypt' if mode=='Encrypt' else 'Decrypt')} {in_path.name} ..."
                draw_status(stdscr, " cryptus_tui — Commander für cryptus.py ", info_line(), status)
                stdscr.refresh()
                try:
                    if mode == "Encrypt":
                        data = in_path.read_bytes()
                        def pcb(frac):
                            draw_progress(stdscr, frac, "encrypt")
                        blob = encrypt_with_progress(data, auth, level, pcb)
                        # roman text
                        roman_text = cryptus.bytes_to_roman_text(blob, block_width=block or 80)
                        # out path
                        base = output_name if (output_name and len(targets)==1) else in_path.name + ".roman"
                        out_path = (right_path / base).resolve()
                        out_path.write_text(roman_text, encoding="utf-8")
                    else:
                        # decrypt expects Roman text → build blob with progress by tokenizing
                        roman_text = in_path.read_text(encoding="utf-8")
                        tokens = roman_text.split()
                        total = len(tokens)
                        blob_bytes = bytearray()
                        for i, tok in enumerate(tokens, 1):
                            blob_bytes.append(cryptus.from_roman(tok))
                            if i % 1024 == 0 or i == total:
                                draw_progress(stdscr, i/total if total else 1.0, "parse")
                        plain = decrypt_with_progress(bytes(blob_bytes), auth, lambda f: draw_progress(stdscr, f, "decrypt"))
                        base = output_name if (output_name and len(targets)==1) else in_path.name + ".dec"
                        out_path = (right_path / base).resolve()
                        out_path.write_bytes(plain)
                    status = f"Fertig: {out_path}"
                except Exception as e:
                    status = f"Fehler bei {in_path.name}: {e}"
                # small pause so user sees completion
                stdscr.refresh()
                time.sleep(0.2)

            # done; clear selection after batch
            selection.clear()

        time.sleep(0.01)

def run():
    curses.wrapper(main)

if __name__ == "__main__":
    run()
