import dataclasses
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pq_session as pq
import main as core


def _exchange(suite="caalc"):
    responder = pq.Identity.generate()
    initiator = pq.Identity.generate()
    offer, pending = pq.create_offer(suite, responder, initiator.public_key)
    offer = pq.Offer.decode(offer.encode())
    response, initiator_context = pq.accept_offer(
        offer, responder.public_key, initiator, responder.fingerprint)
    response = pq.Response.decode(response.encode())
    responder_context, confirmation = pq.finish_offer(
        pending, response, initiator.public_key)
    pq.verify_confirmation(initiator_context, confirmation)
    return responder, initiator, offer, response, initiator_context, responder_context, confirmation


@pytest.mark.parametrize("suite", ["caalc", "ascon"])
def test_authenticated_exchange_and_separate_keys(suite):
    *_, a, b, confirmation = _exchange(suite)
    assert a.traffic_key == b.traffic_key
    assert a.ascon_key == b.ascon_key
    assert a.confirmation_key == b.confirmation_key
    assert a.session_id == b.session_id
    assert a.transcript_hash == b.transcript_hash
    assert a.peer_fingerprint != b.peer_fingerprint
    assert a.suite == suite
    assert len(a.traffic_key) == 16
    assert len(a.ascon_key) == 16
    assert a.traffic_key != a.ascon_key
    assert len(a.session_id) == 8
    assert len(a.transcript_hash) == 32
    assert confirmation == a.confirmation(b"responder")
    assert a.confirmation(b"initiator") != a.confirmation(b"responder")
    cipher = core.engine(suite)
    packet, tag = cipher.encrypt(a.selected_key, b"n" * 16, b"audio frame", b"CAP1 header")
    assert cipher.decrypt(a.selected_key, b"n" * 16, packet, b"CAP1 header", tag) == b"audio frame"
    with pytest.raises(core.AuthenticationError):
        cipher.decrypt(a.selected_key, b"n" * 16, bytes([packet[0] ^ 1]) + packet[1:], b"CAP1 header", tag)


def test_offer_signature_and_identity_pin_reject_changes():
    responder, initiator = pq.Identity.generate(), pq.Identity.generate()
    attacker = pq.Identity.generate()
    offer, _ = pq.create_offer("caalc", responder, initiator.public_key)
    with pytest.raises(pq.SessionError, match="identity"):
        pq.accept_offer(offer, attacker.public_key, initiator, attacker.fingerprint)
    altered = dataclasses.replace(offer, nonce_r=bytes([offer.nonce_r[0] ^ 1]) + offer.nonce_r[1:])
    with pytest.raises(pq.SessionError, match="signature"):
        pq.accept_offer(altered, responder.public_key, initiator, responder.fingerprint)


def test_response_signature_suite_and_confirmation_reject_changes():
    responder, initiator, offer, response, a, b, confirmation = _exchange()
    altered = dataclasses.replace(response, nonce_i=bytes([response.nonce_i[0] ^ 1]) + response.nonce_i[1:])
    _, pending = pq.create_offer("caalc", responder, initiator.public_key)
    # A response from another exchange cannot be replayed into this pending state.
    with pytest.raises(pq.SessionError, match="mismatch"):
        pq.finish_offer(pending, altered, initiator.public_key)
    with pytest.raises(pq.SessionError, match="confirmation"):
        pq.verify_confirmation(a, bytes([confirmation[0] ^ 1]) + confirmation[1:])
    with pytest.raises(pq.SessionError, match="Invalid suite"):
        pq._signature_bytes("unknown", b"x" * 32, b"y" * 32, b"n" * 32, b"k")


def test_invalid_initiator_signature_and_suite_downgrade_rejected():
    responder, initiator = pq.Identity.generate(), pq.Identity.generate()
    offer, pending = pq.create_offer("caalc", responder, initiator.public_key)
    response, _ = pq.accept_offer(offer, responder.public_key, initiator,
                                  responder.fingerprint)
    bad_sig = dataclasses.replace(response,
                                  signature=bytes([response.signature[0] ^ 1]) + response.signature[1:])
    with pytest.raises(pq.SessionError, match="signature"):
        pq.finish_offer(pending, bad_sig, initiator.public_key)
    downgraded = dataclasses.replace(response, suite="ascon")
    with pytest.raises(pq.SessionError, match="mismatch"):
        pq.finish_offer(pending, downgraded, initiator.public_key)


def test_identity_roundtrip(tmp_path):
    ident = pq.Identity.generate()
    pq.save_identity(ident, tmp_path)
    restored = pq.load_identity(tmp_path)
    assert restored == ident
    if os.name != 'nt':
        assert (tmp_path / "identity.secret").stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("suite", ["caalc", "ascon"])
def test_written_session_file_loads_for_hardware_provisioning(tmp_path, suite):
    import hardware_session
    path = tmp_path / f"{suite}.session.json"
    report = pq.demo_exchange(suite, path)
    key, sid, loaded_suite = hardware_session.read_pq_session(path)
    assert report["key_material_written"]
    assert loaded_suite == suite and len(key) == 16 and len(sid) == 8
    if os.name != 'nt':
        assert path.stat().st_mode & 0o777 == 0o600
    assert "traffic_key_hex" not in report
    pcm = b"\x34\x12" * 160
    packet = core.make_packet(key, sid, 0, 8000, 20, pcm, algorithm=loaded_suite)
    assert core.SessionReceiver(key, sid, loaded_suite).accept(packet) == (0, 8000, 20, pcm)


def test_hardware_rejects_malformed_pq_session_file(tmp_path):
    import hardware_session
    path = tmp_path / "bad.session.json"
    path.write_text('{"format":"CAALC-PQS1-SESSION","version":1,"suite":"caalc","traffic_key_hex":"00","session_id_hex":"00"}')
    with pytest.raises(ValueError, match="length"):
        hardware_session.read_pq_session(path)


def test_handshake_bounds_and_malformed_message():
    with pytest.raises(pq.SessionError, match="limit"):
        pq.Offer.decode(b" " * (pq.MAX_MESSAGE + 1))
    with pytest.raises(pq.SessionError, match="Malformed"):
        pq.Response.decode(b"not-json")
