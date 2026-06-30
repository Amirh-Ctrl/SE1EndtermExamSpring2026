# Secure Messenger Code

## Contents

- `src/secure_messenger/crypto`: End-to-end encryption with X25519, HKDF-SHA256, and ChaCha20-Poly1305
- `src/secure_messenger/domain`: Domain models and domain exceptions
- `src/secure_messenger/server`: Application service, SQLite repository, and HTTP API
- `src/secure_messenger/client`: HTTP client and local profile storage
- `src/secure_messenger/cli.py`: Command-line interface for running the main scenarios
- `Dockerfile`: Ready to be used for the CD question

## Sample Run

```powershell
cd 40031701
$env:PYTHONPATH="src"
python -m secure_messenger server --host 127.0.0.1 --port 8080 --db data/messenger.db
```

In another terminal:

```powershell
cd 40031701
$env:PYTHONPATH="src"
python -m secure_messenger init-user alice --password alice-pass-123 --server-url http://127.0.0.1:8080 --profiles-dir profiles
python -m secure_messenger init-user bob --password bob-pass-123 --server-url http://127.0.0.1:8080 --profiles-dir profiles
python -m secure_messenger send alice bob --message "Hello Bob" --password alice-pass-123 --server-url http://127.0.0.1:8080 --profiles-dir profiles
python -m secure_messenger inbox bob --password bob-pass-123 --server-url http://127.0.0.1:8080 --profiles-dir profiles
```

