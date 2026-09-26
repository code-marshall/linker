# Linker

A password-locked link vault. One Python process serves the UI and does the
crypto — there is no separate frontend to build or run.

Each collection is a single file in `collections/` encrypted end-to-end with
**AES-256-GCM**, keyed by **PBKDF2-HMAC-SHA256** (600,000 iterations) over your
password. Link names, addresses and notes only exist as ciphertext on disk.

## Run

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python app.py          # http://127.0.0.1:5001  (PORT=8080 to change)
```

## Use

1. Create a collection with a name and a password (8+ characters).
2. It unlocks immediately — add links (name, address, optional note).
3. Locked collections show only a password prompt. Nothing else renders.
4. Search, edit and delete links; change the password; delete the collection
   (deleting requires the password, so it can't be wiped by a bystander).

Collections auto-lock after 30 minutes idle, on "Lock now"/"Lock all", and
whenever the server restarts.

## How the encryption works

| | |
|---|---|
| Cipher | AES-256-GCM (authenticated — a wrong password fails, it never yields garbage) |
| Key derivation | PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte random salt per file |
| Nonce | 12 random bytes, regenerated on **every** write |
| Stored plaintext | none — only the slug filename, salt, nonce and ciphertext |

A file on disk looks like this, and that's all it ever contains:

```json
{"v":1,"kdf":{"name":"pbkdf2-sha256","iterations":600000,"salt":"..."},
 "nonce":"...","ciphertext":"..."}
```

The password is never written to disk and never put in a cookie. While a
collection is unlocked the password is held in the server process, in memory,
keyed to your session id; the browser cookie holds only that opaque id.

## Layout

```
app.py            Flask routes + in-memory session keyring
vault.py          encrypt / decrypt / read / save — all crypto lives here
templates/        base, index, unlock, collection, 404
static/style.css  dark theme, follows the OS for light mode
collections/      encrypted .enc files (gitignored)
```

## Caveats

- **There is no password reset.** Lose the password and the collection is gone.
- Collection *filenames* are a slug of the name and are readable on disk; the
  contents are not. Name a collection `notes` rather than something revealing
  if that matters.
- The dev server binds to `127.0.0.1` only. It is a local single-user tool —
  put it behind a real WSGI server and HTTPS before exposing it to a network.
