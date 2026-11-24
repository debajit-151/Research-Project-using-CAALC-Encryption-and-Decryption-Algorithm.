"""Demo authenticated key establishment using ML-KEM-512 and ML-DSA-44.

This protocol is for an academic demonstration. Production deployments should
use a reviewed channel protocol. Identity keys are pinned by SHA-256 fingerprint.
"""
from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.kem import ml_kem_512
from pqcrypto.sign import ml_dsa_44

VERSION = 1
SUITES = {"caalc": 0, "ascon": 1}
DOMAIN = b"CAALC-128-v1/PQS1"
MAX_MESSAGE = 16384


class SessionError(ValueError):
    """Invalid, unauthenticated, or incompatible handshake data."""


def _pack_fields(*fields: bytes) -> bytes:
    result = bytearray()
    for field in fields:
        if len(field) > 65535:
            raise SessionError("Handshake field exceeds limit")
        result.extend(struct.pack("!H", len(field)))
        result.extend(field)
    if len(result) > MAX_MESSAGE:
        raise SessionError("Handshake message exceeds limit")
    return bytes(result)


def _signature_bytes(suite: str, responder_id: bytes, initiator_id: bytes,
                     nonce_r: bytes, kem_public: bytes,
                     kem_ciphertext: bytes = b"", nonce_i: bytes = b"") -> bytes:
    if not isinstance(suite, str) or suite not in SUITES or len(responder_id) != 32 or len(initiator_id) != 32:
        raise SessionError("Invalid suite or identity fingerprint")
    if len(nonce_r) != 32 or (nonce_i and len(nonce_i) != 32):
        raise SessionError("Invalid handshake nonce")
    return _pack_fields(DOMAIN, bytes([VERSION, SUITES[suite]]), responder_id,
                        initiator_id, nonce_r, nonce_i, kem_public, kem_ciphertext)


@dataclass(frozen=True)
class SessionContext:
    suite: str
    traffic_key: bytes
    ascon_key: bytes
    confirmation_key: bytes
    session_id: bytes
    transcript_hash: bytes
    peer_fingerprint: bytes

    @property
    def selected_key(self) -> bytes:
        """Return the purpose-specific key for this session's chosen AEAD."""
        return self.traffic_key if self.suite == "caalc" else self.ascon_key

    def confirmation(self, role: bytes) -> bytes:
        if role not in (b"initiator", b"responder"):
            raise SessionError("Unknown confirmation role")
        return hmac.digest(self.confirmation_key,
                           DOMAIN + b"/confirm/" + role + self.transcript_hash,
                           "sha256")


@dataclass(frozen=True)
class Identity:
    public_key: bytes
    secret_key: bytes

    @classmethod
    def generate(cls) -> "Identity":
        public_key, secret_key = ml_dsa_44.keygen()
        return cls(bytes(public_key), bytes(secret_key))

    @property
    def fingerprint(self) -> bytes:
        return hashlib.sha256(self.public_key).digest()


@dataclass(frozen=True)
class Offer:
    suite: str
    responder_id: bytes
    nonce_r: bytes
    kem_public: bytes
    signature: bytes

    def encode(self) -> bytes:
        return json.dumps({"v": VERSION, "suite": self.suite,
                           "responder_id": self.responder_id.hex(),
                           "nonce_r": self.nonce_r.hex(),
                           "kem_public": base64.b64encode(self.kem_public).decode(),
                           "signature": base64.b64encode(self.signature).decode()},
                          separators=(",", ":")).encode()

    @classmethod
    def decode(cls, raw: bytes) -> "Offer":
        if len(raw) > MAX_MESSAGE:
            raise SessionError("Handshake message exceeds limit")
        try:
            o = json.loads(raw)
            if o["v"] != VERSION:
                raise SessionError("Unsupported handshake version")
            result = cls(o["suite"], bytes.fromhex(o["responder_id"]),
                         bytes.fromhex(o["nonce_r"]),
                         base64.b64decode(o["kem_public"], validate=True),
                         base64.b64decode(o["signature"], validate=True))
        except SessionError:
            raise
        except Exception as exc:
            raise SessionError("Malformed handshake offer") from exc
        if not isinstance(result.suite, str) or result.suite not in SUITES or len(result.responder_id) != 32 or len(result.nonce_r) != 32:
            raise SessionError("Malformed handshake offer fields")
        if len(result.kem_public) != ml_kem_512.PUBLIC_KEY_SIZE or len(result.signature) != ml_dsa_44.SIGNATURE_SIZE:
            raise SessionError("Unexpected handshake field length")
        return result


@dataclass(frozen=True)
class Response:
    suite: str
    responder_id: bytes
    initiator_id: bytes
    nonce_r: bytes
    nonce_i: bytes
    kem_public: bytes
    kem_ciphertext: bytes
    signature: bytes

    def encode(self) -> bytes:
        return json.dumps({"v": VERSION, "suite": self.suite,
                           "responder_id": self.responder_id.hex(),
                           "initiator_id": self.initiator_id.hex(),
                           "nonce_r": self.nonce_r.hex(), "nonce_i": self.nonce_i.hex(),
                           "kem_public": base64.b64encode(self.kem_public).decode(),
                           "kem_ciphertext": base64.b64encode(self.kem_ciphertext).decode(),
                           "signature": base64.b64encode(self.signature).decode()},
                          separators=(",", ":")).encode()

    @classmethod
    def decode(cls, raw: bytes) -> "Response":
        if len(raw) > MAX_MESSAGE:
            raise SessionError("Handshake message exceeds limit")
        try:
            o = json.loads(raw)
            if o["v"] != VERSION:
                raise SessionError("Unsupported handshake version")
            result = cls(o["suite"], bytes.fromhex(o["responder_id"]),
                         bytes.fromhex(o["initiator_id"]), bytes.fromhex(o["nonce_r"]),
                         bytes.fromhex(o["nonce_i"]),
                         base64.b64decode(o["kem_public"], validate=True),
                         base64.b64decode(o["kem_ciphertext"], validate=True),
                         base64.b64decode(o["signature"], validate=True))
        except SessionError:
            raise
        except Exception as exc:
            raise SessionError("Malformed handshake response") from exc
        if not isinstance(result.suite, str) or result.suite not in SUITES or any(len(x) != 32 for x in
                (result.responder_id, result.initiator_id, result.nonce_r, result.nonce_i)):
            raise SessionError("Malformed handshake response fields")
        if (len(result.kem_public) != ml_kem_512.PUBLIC_KEY_SIZE or
                len(result.kem_ciphertext) != ml_kem_512.CIPHERTEXT_SIZE or
                len(result.signature) != ml_dsa_44.SIGNATURE_SIZE):
            raise SessionError("Unexpected handshake field length")
        return result


@dataclass(frozen=True)
class PendingResponder:
    offer: Offer
    kem_secret: bytes
    identity: Identity
    initiator_fingerprint: bytes


def _derive(shared: bytes, transcript: bytes, suite: str,
            peer_fingerprint: bytes) -> SessionContext:
    th = hashlib.sha256(transcript).digest()
    material = HKDF(algorithm=hashes.SHA256(), length=72, salt=th,
                    info=DOMAIN + b"/HKDF/" + suite.encode("ascii")).derive(shared)
    return SessionContext(suite, material[:16], material[16:32], material[32:64],
                          material[64:72], th, peer_fingerprint)


def create_offer(suite: str, responder: Identity, initiator_public: bytes):
    """Responder starts a fresh exchange; returns offer and one-use state."""
    if suite not in SUITES:
        raise SessionError("Unsupported cipher suite")
    kem_public, kem_secret = ml_kem_512.keygen()
    nonce_r = secrets.token_bytes(32)
    initiator_id = hashlib.sha256(initiator_public).digest()
    unsigned = _signature_bytes(suite, responder.fingerprint, initiator_id,
                                nonce_r, bytes(kem_public))
    offer = Offer(suite, responder.fingerprint, nonce_r, bytes(kem_public),
                  bytes(ml_dsa_44.sign(responder.secret_key, unsigned)))
    return offer, PendingResponder(offer, bytes(kem_secret), responder, initiator_id)


def accept_offer(offer: Offer, responder_public: bytes, initiator: Identity,
                 expected_responder_fingerprint: bytes):
    """Verify offer against pinned responder, then create signed KEM response."""
    if not hmac.compare_digest(hashlib.sha256(responder_public).digest(), expected_responder_fingerprint):
        raise SessionError("Responder identity fingerprint mismatch")
    if not hmac.compare_digest(offer.responder_id, expected_responder_fingerprint):
        raise SessionError("Offer identity mismatch")
    unsigned = _signature_bytes(offer.suite, offer.responder_id,
                                initiator.fingerprint, offer.nonce_r,
                                offer.kem_public)
    try:
        ml_dsa_44.verify(responder_public, unsigned, offer.signature)
    except Exception as exc:
        raise SessionError("Responder signature invalid") from exc
    ciphertext, shared = ml_kem_512.encaps(offer.kem_public)
    nonce_i = secrets.token_bytes(32)
    transcript = _signature_bytes(offer.suite, offer.responder_id,
                                  initiator.fingerprint, offer.nonce_r,
                                  offer.kem_public, bytes(ciphertext), nonce_i)
    sig = bytes(ml_dsa_44.sign(initiator.secret_key, transcript))
    response = Response(offer.suite, offer.responder_id, initiator.fingerprint,
                        offer.nonce_r, nonce_i, offer.kem_public,
                        bytes(ciphertext), sig)
    context = _derive(bytes(shared), transcript, offer.suite, offer.responder_id)
    return response, context


def finish_offer(pending: PendingResponder, response: Response,
                 initiator_public: bytes):
    """Verify initiator signature, decapsulate and derive the identical context."""
    offer = pending.offer
    initiator_fp = hashlib.sha256(initiator_public).digest()
    if (not hmac.compare_digest(initiator_fp, pending.initiator_fingerprint) or
            not hmac.compare_digest(response.initiator_id, initiator_fp) or
            not hmac.compare_digest(response.responder_id, pending.identity.fingerprint) or
            response.suite != offer.suite or response.nonce_r != offer.nonce_r or
            response.kem_public != offer.kem_public):
        raise SessionError("Handshake identity or transcript mismatch")
    transcript = _signature_bytes(response.suite, response.responder_id,
                                  response.initiator_id, response.nonce_r,
                                  response.kem_public, response.kem_ciphertext,
                                  response.nonce_i)
    try:
        ml_dsa_44.verify(initiator_public, transcript, response.signature)
        shared = ml_kem_512.decaps(pending.kem_secret, response.kem_ciphertext)
    except Exception as exc:
        raise SessionError("Initiator signature or KEM validation failed") from exc
    context = _derive(bytes(shared), transcript, response.suite, initiator_fp)
    return context, context.confirmation(b"responder")


def verify_confirmation(context: SessionContext, confirmation: bytes) -> None:
    if not hmac.compare_digest(confirmation, context.confirmation(b"responder")):
        raise SessionError("Key confirmation failed")


def save_identity(identity: Identity, directory) -> None:
    """Save a local demo identity; secret key file is owner-only on POSIX."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "identity.public.json").write_text(json.dumps({
        "algorithm": "ML-DSA-44", "public_key": base64.b64encode(identity.public_key).decode(),
        "fingerprint": identity.fingerprint.hex()}, indent=2) + "\n")
    secret_path = directory / "identity.secret"
    secret_path.write_bytes(identity.secret_key)
    try:
        os.chmod(secret_path, 0o600)
    except OSError:
        pass


def save_session_material(context: SessionContext, path) -> None:
    """Write explicit demo-only AEAD key and nonce prefix for USB provisioning."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "format": "CAALC-PQS1-SESSION",
        "version": VERSION,
        "suite": context.suite,
        "traffic_key_hex": context.selected_key.hex(),
        "session_id_hex": context.session_id.hex(),
        "transcript_hash": context.transcript_hash.hex(),
        "peer_fingerprint": context.peer_fingerprint.hex(),
    }
    path.write_text(json.dumps(document, indent=2) + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def load_identity(directory) -> Identity:
    directory = Path(directory)
    try:
        public_doc = json.loads((directory / "identity.public.json").read_text())
        public_key = base64.b64decode(public_doc["public_key"], validate=True)
        secret_key = (directory / "identity.secret").read_bytes()
        identity = Identity(public_key, secret_key)
        if (public_doc["algorithm"] != "ML-DSA-44" or
                len(public_key) != ml_dsa_44.PUBLIC_KEY_SIZE or
                len(secret_key) != ml_dsa_44.SECRET_KEY_SIZE or
                not hmac.compare_digest(identity.fingerprint.hex(), public_doc["fingerprint"])):
            raise SessionError("Identity files are inconsistent")
        return identity
    except SessionError:
        raise
    except Exception as exc:
        raise SessionError("Could not load identity") from exc


def demo_exchange(suite: str = "caalc", session_file=None) -> dict:
    """Run both logical gateway roles locally and exercise authenticated audio AEAD."""
    responder = Identity.generate()
    initiator = Identity.generate()
    offer, pending = create_offer(suite, responder, initiator.public_key)
    decoded_offer = Offer.decode(offer.encode())
    response, initiator_context = accept_offer(
        decoded_offer, responder.public_key, initiator, responder.fingerprint)
    decoded_response = Response.decode(response.encode())
    responder_context, confirmation = finish_offer(
        pending, decoded_response, initiator.public_key)
    verify_confirmation(initiator_context, confirmation)
    if not (hmac.compare_digest(initiator_context.traffic_key,
                                responder_context.traffic_key) and
            hmac.compare_digest(initiator_context.transcript_hash,
                                responder_context.transcript_hash)):
        raise SessionError("Peer session derivation mismatch")
    import main as core
    cipher = core.engine(suite)
    nonce, ad, plaintext = os.urandom(16), b"CAP1 demo metadata", b"authenticated audio frame"
    ciphertext, tag = cipher.encrypt(initiator_context.selected_key, nonce, plaintext, ad)
    recovered = cipher.decrypt(responder_context.selected_key, nonce, ciphertext, ad, tag)
    tampered = bytearray(ciphertext)
    tampered[0] ^= 1
    try:
        cipher.decrypt(responder_context.selected_key, nonce, bytes(tampered), ad, tag)
    except core.AuthenticationError:
        tamper_rejected = True
    else:
        raise SessionError("Tampered audio unexpectedly authenticated")
    if session_file:
        save_session_material(initiator_context, session_file)
    return {
        "mode": "single-device logical gateway demonstration",
        "suite": suite,
        "kem": "ML-KEM-512",
        "identity_signature": "ML-DSA-44",
        "receiver_signature_verified": True,
        "sender_signature_verified": True,
        "key_confirmation_verified": True,
        "traffic_keys_match": True,
        "transcript_hash": initiator_context.transcript_hash.hex(),
        "receiver_fingerprint": responder.fingerprint.hex(),
        "sender_fingerprint": initiator.fingerprint.hex(),
        "audio_roundtrip": recovered == plaintext,
        "tampered_audio_rejected": tamper_rejected,
        "key_material_written": bool(session_file),
        "session_file": str(session_file) if session_file else None,
        "claim": "Demo protocol only; use a reviewed secure-channel protocol for deployment.",
    }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=sorted(SUITES), default="caalc")
    parser.add_argument("--write-session", help="Explicitly save demo traffic key/session ID for the trusted-USB hardware path (owner-only file)")
    args = parser.parse_args()
    print(json.dumps(demo_exchange(args.suite, args.write_session), indent=2))
