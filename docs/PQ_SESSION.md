# Authenticated post-quantum session demonstration

## Purpose and boundary

The project now includes an academic demonstration of ML-KEM-512 key establishment and ML-DSA-44 identity signatures. It runs the two logical gateway roles in one process for repeatable verification. The identities are separate keypairs and are explicitly pinned by their SHA-256 fingerprints. This demonstrates the protocol flow; it is not a reviewed transport protocol or a claim that CAALC itself is post-quantum secure.

For a hardware presentation, the laptop can explicitly write the selected 16-byte traffic key and matching session ID to an owner-only file, then provision them to the ESP32 over trusted USB. The ESP32 performs audio AEAD and packetization. It does not run ML-KEM or ML-DSA, and the two handshake roles are still local logical endpoints.

## Run the demonstration

Install project dependencies, build the native reference libraries, and execute:

```bash
python build_native.py
python -m pq_session --suite caalc
python -m pq_session --suite ascon
python -m pytest tests/test_pq_session.py -q
```

The command prints public fingerprints, transcript hash, successful key confirmation, audio round-trip status, and tamper rejection. It does not save either identity private key or the session key unless `--write-session PATH` is explicitly supplied. That option writes a cleartext, owner-only demo file containing the selected traffic key, suite and matching session ID. The file is ignored by Git; protect it and delete it after the demo. Example end-to-end USB loopback:

```bash
python -m pq_session --suite ascon --write-session results/ascon-demo.session.json
python hardware_session.py --serial COM5 --mode USB --session-file results/ascon-demo.session.json --wav results/original.wav --seconds 4 --out results/pq_usb_received.wav
```

The hardware runner selects the cipher and nonce prefix from the session file. This is local session establishment followed by trusted USB provisioning, not a network handshake with the ESP32.

## Exchange flow

1. The responder generates an ephemeral ML-KEM-512 keypair and a random 32-byte challenge. It signs protocol version, selected suite, both pinned identities, challenge and ephemeral public key using its ML-DSA-44 identity.
2. The initiator checks the responder's pinned fingerprint and signature, encapsulates a shared secret to the ephemeral KEM key, creates a random nonce and signs the complete transcript.
3. The responder verifies the initiator's pinned identity and transcript signature, then decapsulates the ciphertext.
4. Both sides derive the same session ID, CAALC traffic key, independent Ascon key and confirmation key with HKDF-SHA256. The initiator verifies the responder's HMAC key confirmation before accepting the session.
5. The selected traffic key protects the framed audio. Audio ciphertext and tags are checked before plaintext becomes available to playback.

The signed fields bind the protocol version, cipher suite, identities, nonces and KEM material. Length-prefixed transcript fields avoid ambiguous concatenation. Handshake messages have a 16 KiB maximum. Unsupported suites, wrong fingerprints, modified signatures, altered transcript fields, malformed encoding and invalid key confirmation fail closed.

## Local identity files

`save_identity()` writes `identity.public.json` and `identity.secret` into the caller-selected directory. The secret file is set to owner read/write permissions on POSIX systems. Keep the directory outside Git; the project `.gitignore` excludes the default `identities/` path. Back up identity files securely if a stable identity is needed. The public fingerprint shown to the peer must be exchanged out of band and checked by a person before pinning it.

## Limits

The current demo runs both roles on one device and does not provide a network listener, certificates, persistent replay database, secure element, or protection against malware already running on the laptop. Its protocol implementation is intended for study and demonstration. For actual confidential communications, use a reviewed secure-channel implementation and standardized AEAD such as Ascon-AEAD128.
