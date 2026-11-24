# CAALC-128 v1: reproducible experimental specification

**Status:** unreviewed research construction, not a standardized AEAD or a cipher with a demonstrated security level. “128” denotes key/tag/nonce sizes, not a proven strength. No production use is justified by the tests in this package. Ascon-AEAD128 is a separate standardized option, never the novel contribution.

## Representation and permutation

A state consists of twelve unsigned 32-bit words, serialized in order `S0,...,S11`, each little endian, for 48 bytes. `L=S[0:6]`, `R=S[6:12]`. Every NOT is restricted to 32 bits. Rotations wrap within a word. Indices in F are modulo six; updates are simultaneous, never in-place neighbor updates.

For i=0..5:

`F_i(R) = R_i XOR ROTL32(R_i,1) XOR (ROTL32(R_(i-1),7) AND NOT32(ROTL32(R_(i+1),13))) XOR ROTL32(R_(i+2),17)`.

For r=0..23:

`(L',R') = (R, L XOR F(R) XOR C_r)`.

The inverse, with round constants in reverse order, is:

`R = L'`, `L = R' XOR F(L') XOR C_r`.

Substituting the forward equations gives `R'=L XOR F(R) XOR C_r`, so `R' XOR F(L') XOR C_r=L`. Consequently the network is bijective for **any** deterministic F. This proves invertibility, not unpredictability or resistance to cryptanalysis. F itself need not be bijective. Audio AEAD decryption uses the **forward** permutation; the inverse exists for validation and mathematical explanation.

Constants: for round r, compute `SHA256(ASCII("CAALC-128-v1/round/") || uint8(r))`. Take the first 24 digest bytes and decode six little-endian words. r begins at zero. All 144 exact words are in `firmware/include/round_constants.h` and `test_vectors/caalc_vectors.json`. SHA-256 is used only to derive fixed public constants offline; it is not executed in the embedded round loop. Constants distinguish rounds and word positions. They are not round keys. The key enters the duplex initialization and finalization; this design deliberately has no separate secret-key schedule.

F is a **CA-inspired word-oriented nonlinear transformation**. Its local neighborhood consists of words i−1, i, i+1, i+2 with periodic boundaries. Rotations select different bit positions within those words. AND with NOT contributes a degree-two Boolean term; XOR combines terms. This is not an exact elementary CA rule, nor a proof that a CA provides security. Cross-word and within-word propagation are measured separately from security claims.

## AEAD definition

Public permutation `P`: the full 24-round permutation above. Byte indices are zero-based. Rate bytes are 0..15 and capacity bytes 16..47. Key K, nonce N and tag T are each 16 bytes. IV is the **16-byte** ASCII string `CAALC128-AEAD-v1` (no terminator). Define `D(S,d)=P(S with byte 47 XOR d)`.

1. Initialization: `S = D(IV || K || N, 0x01)`.
2. Associated data A: for every full 16-byte block, XOR it into S[0:16] and apply D with 0x02. **Always** process one final tail block, including an empty tail after an exact multiple: XOR tail bytes at rate offset zero, XOR `0x80` at byte `len(tail)`, then apply D with 0x03. Unused rate bytes are left as-is. This is XOR padding into state, not overwriting remaining state with zeros.
3. Message: for each full plaintext block M, compute C=M XOR S[0:16], **replace** S[0:16] with C, and apply D with 0x04. On decryption, compute M=C XOR S[0:16], then replace rate bytes with received C. Keep recovered plaintext private.
4. Final message tail: compute each C[i]=M[i] XOR S[i] for i<len(tail), replace these S bytes with C, XOR `0x80` into S[len(tail)], then D with 0x05. This operation is mandatory even for empty plaintext or an exact block multiple. Tail length is 0..15.
5. XOR `LE64(len(A)) || LE64(len(M))` into S[16:32]. Lengths count **bytes**, not bits. XOR K into S[32:48], then apply D with 0x06.
6. Tag: `T = S[16:32] XOR K`. Return C,T.
7. Decryption recomputes the tag from the received ciphertext and AD and compares all 16 bytes using `hmac.compare_digest` in Python or an accumulated XOR/OR in C++. On failure, Python returns no plaintext; C++ clears its private output buffer. Caller must not consume the private buffer before successful return. No unauthenticated samples reach playback.

Domain codes 01..06 distinguish initialization, full AD, final AD, full message, final message, and finalization. Even empty AD and messages have distinct padded transitions. This is a newly selected experimental duplex mode, **not** a claimed instantiation of a proven mode theorem. Domain separation and capacity sizing alone are not a proof.

Pseudocode:

```text
ENCRYPT(K,N,M,A):
    validate sizes
    S = D(IV || K || N, 1)
    for B in full_blocks(A): S.rate ^= B; S = D(S,2)
    S.rate[0:len(A.tail)] ^= A.tail
    S[len(A.tail)] ^= 0x80; S = D(S,3)
    for B in full_blocks(M):
        C.block = B XOR S.rate; S.rate = C.block; S = D(S,4)
    C.tail = M.tail XOR S.rate prefix
    replace S prefix with C.tail; S[len(M.tail)] ^= 0x80; S = D(S,5)
    S[16:32] ^= LE64(len(A)) || LE64(len(M))
    S[32:48] ^= K; S = D(S,6)
    return C, S[16:32] XOR K

DECRYPT(K,N,C,A,T):
    run the same state transitions, using received C for rate replacement
    keep C XOR rate in private memory
    recompute expected tag
    if constant_time_equal(T,expected): release private plaintext
    else: discard plaintext and report authentication failure
```

## Limits, nonce handling and key separation

The generic API rejects AD or message lengths above 65,536 bytes. Streaming audio is framed into at most 1,280-byte messages, so large recordings do not require one oversized AEAD call. API callers are responsible for nonce uniqueness. Fixed zero keys/nonces in vector and benchmark files are **public tests**, not deployment keys.

A packet nonce is `session_id[8] || LE64(sequence)`. Sequence starts at zero, is never reused, and must be below 2^32. Firmware refuses exhaustion. Use a **fresh key for every hardware boot/session**; the provided `hardware_session.py` creates it automatically, or accepts a fresh ML-KEM-derived key. Firmware deliberately forgets its key on reset. Reusing the same provisioning key/session pair after a reset would repeat nonces and is forbidden. The minimal firmware does not contain a persistent registry of past keys.

Offline containers generate a cryptographically random 64-bit session ID. For q containers under a reused key, collision probability is approximately q(q−1)/2^65. Prefer a new key per file; this package's operational ceiling is 2^16 containers per reused key and at most 2^32 total plaintext bytes per key. The application does not maintain a global cross-process usage database; operators must rotate keys. These conservative usage policies **do not establish a security bound** for CAALC.

K is a purpose-specific traffic key. ML-KEM shared secrets are processed by HKDF-SHA256 with salt `SHA256(public_key || kem_ciphertext)` and info `CAALC-128-v1/audio/sender-to-receiver`; output length 16. Reverse direction, other protocols and cipher suites require different info values and different derived keys. The benchmark intentionally uses identical public test keys for controlled comparison. Do not reuse an actual CAALC traffic key in Ascon sessions.

## Wire format (little endian)

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | ASCII CAP1 |
| 4 | 1 | Version 1 |
| 5 | 1 | Algorithm 0=CAALC, 1=Ascon |
| 6 | 8 | Session identifier |
| 14 | 8 | Sequence number (restricted to <2^32) |
| 22 | 2 | Sample rate 8000 or 16000 |
| 24 | 2 | Frame duration 10, 20 or 40 ms |
| 26 | 2 | Payload bytes, even, ≤rate×duration/1000×2 |
| 28 | n | Ciphertext |
| 28+n | 16 | Authentication tag |

All 28 header bytes are associated data. UDP packet overhead is 44 bytes, excluding UDP/IP/Wi-Fi: at 320 bytes that is 13.75%. USB adds `CA || LE16(packet_length)` (4 bytes). USB PCM input is `PC || LE16(320) || 320 PCM bytes`. Diagnostic ASCII lines may coexist on serial. Firmware v1 captures 8 kHz/20 ms only; Python supports all specified rates and frame sizes. Stream format changes require a new session.

The receiver is pinned to the expected session ID and algorithm. It authenticates first, checks a 64-position replay bitmap, then inserts into a bounded 64-frame jitter queue. An 80 ms startup delay allows reordering; deadlines consume audio in sequence, substituting silence for absent frames. Late frames are discarded. Start reception before transmission; joining a stream far beyond sequence zero is not implemented. Authentication cannot prevent packet dropping, traffic analysis or denial of service. Silence inserted for loss is local concealment, not accepted forged audio.

## Authenticated file container

Header: `<4sBB8sHHQ>`: `CAF1`, version 1, algorithm ID, session ID, rate, frame milliseconds, total PCM byte count. Header length 26. Each record is `LE16(packet_length) || CAP1 packet`. The **entire container header is appended to each packet's AD**. File records must be contiguous from sequence zero, have the announced frame sizes, and reconstruct exactly the declared total. Exactly one empty authenticated frame represents empty audio. Missing, reordered, extra and truncated records are rejected. Container packets are intentionally distinct from live packets because their AD includes file metadata. No key is stored in a container.

## Known limitations

The raw F commutes with common bit rotations and cyclic shifts of its six word positions. Unequal constants break these exact symmetries in the full tested permutation, but do not establish resistance to rotational/differential cryptanalysis. Early rounds have low diffusion by Feistel design. Tests cover selected repeated-word, zero, all-one and alternating-bit states; untested invariants may exist. No differential trail bounds, linear hull analysis, algebraic attack analysis, quantum attack analysis, side-channel resistance, fault resistance, or formal AEAD proof is provided. No critical functional defect was found in the executed screening; this is not evidence that no critical cryptographic defect exists.
