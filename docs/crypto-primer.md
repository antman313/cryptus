# Kryptographie-Grundlagen (für Schüler) – am Beispiel von **Cryptus**

Dieses Projekt zeigt **grundlegend**, wie moderne Verschlüsselung aufgebaut ist – mit Bausteinen aus der Python-Standardbibliothek.
Es ist **nur zu Lernzwecken** gedacht (kein Ersatz für auditierte Tools).

## Bausteine

1. **Passphrase → Schlüssel**: Wir nutzen **PBKDF2-HMAC-SHA256** als *Key Derivation Function* (KDF).
   - Iterationen = `200.000 × Level` → Level 1–10 erhöht die Rechenarbeit für Angreifer.
   - KDF braucht einen **Salt** (16 Byte), damit gleiche Passwörter **verschiedene** Schlüssel ergeben.

2. **Stromchiffre**: Aus dem Schlüssel erzeugen wir einen **Pseudo-Zufallsstrom** (Keystream) mit **HMAC-SHA256** im *Counter Mode*.
   - Für Block `i` berechnen wir: `HMAC(key, nonce || counter)`.
   - **XOR** mit dem Klartext ergibt den Geheimtext: `cipher = plain XOR keystream`.

3. **Integrität (Manipulationsschutz)**: Nach dem Verschlüsseln rechnen wir eine **HMAC-SHA256** über **Header + Ciphertext** (*encrypt-then-MAC*).
   - Beim Entschlüsseln wird dieser Tag geprüft. Stimmt er nicht → falsches Passwort oder Datei beschädigt.

4. **Roman-Zahlen-Encoding**: Wir kodieren jedes Byte (0–255) als **römische Zahl** (0 → `N`, 65 → `LXV`).
   - Das ist **nur Darstellung**, kein zusätzlicher Schutz.

## Dateiformat (Header)

```
MAGIC "CRY1" (4) | SALT (16) | NONCE (12) | LEVEL (u32, big endian) | CIPHERTEXT | TAG (32)
```

- **SALT**: Zufällig, für KDF
- **NONCE**: Zufällig, für Keystream
- **LEVEL**: PBKDF2-Workfactor (1–10)
- **TAG**: HMAC-SHA256 über `header + ciphertext`

## Wichtig: Sicherheitshinweis

- **Cryptus** ist ein **Lehrprojekt**. Für echte Sicherheit nutze etablierte Tools (z. B. age, OpenSSL, GPG).
- Schwache Passwörter bleiben schwach. Wähle eine gute Passphrase (lang, ungewöhnlich).

Viel Spaß beim Experimentieren!
