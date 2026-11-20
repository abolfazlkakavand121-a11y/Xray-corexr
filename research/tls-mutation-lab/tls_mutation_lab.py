#!/usr/bin/env python3
"""Controlled TLS ClientHello mutation probe. Python standard library only."""
from __future__ import annotations
import argparse, csv, json, socket, ssl, sys, time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

class ClientHelloError(ValueError):
    pass

def _u16(data: bytes, offset: int) -> int:
    if offset + 2 > len(data): raise ClientHelloError("truncated uint16")
    return int.from_bytes(data[offset:offset + 2], "big")

def _record(content_type: int, version: bytes, payload: bytes) -> bytes:
    if len(version) != 2 or len(payload) > 65535: raise ClientHelloError("invalid TLS record")
    return bytes((content_type,)) + version + len(payload).to_bytes(2, "big") + payload

def _extract_client_hello(wire: bytes) -> tuple[bytes, bytes]:
    if len(wire) < 9 or wire[0] != 22: raise ClientHelloError("expected a TLS handshake record")
    version, record_len = wire[1:3], _u16(wire, 3)
    if 5 + record_len > len(wire): raise ClientHelloError("truncated TLS record")
    handshake = wire[5:5 + record_len]
    if len(handshake) < 4 or handshake[0] != 1: raise ClientHelloError("first handshake message is not ClientHello")
    msg_len = int.from_bytes(handshake[1:4], "big")
    if 4 + msg_len > len(handshake): raise ClientHelloError("ClientHello spans multiple input records; unsupported capture")
    return version, handshake[:4 + msg_len]

def _hello_parts(handshake: bytes) -> tuple[bytes, list[tuple[int, bytes]]]:
    if len(handshake) < 4 or handshake[0] != 1: raise ClientHelloError("not a ClientHello")
    body, p = handshake[4:], 0
    if len(body) < 35: raise ClientHelloError("truncated ClientHello body")
    p += 34
    sid_len = body[p]; p += 1 + sid_len
    if p + 2 > len(body): raise ClientHelloError("truncated cipher-suite length")
    suites_len = _u16(body, p); p += 2 + suites_len
    if p >= len(body): raise ClientHelloError("truncated compression methods")
    comp_len = body[p]; p += 1 + comp_len
    if p + 2 > len(body): raise ClientHelloError("ClientHello has no complete extensions length")
    ext_len = _u16(body, p); prefix_end = p; p += 2
    if p + ext_len != len(body): raise ClientHelloError("extension block length mismatch")
    extensions = []
    while p < len(body):
        if p + 4 > len(body): raise ClientHelloError("truncated extension header")
        typ, size = _u16(body, p), _u16(body, p + 2); p += 4
        if p + size > len(body): raise ClientHelloError("truncated extension payload")
        extensions.append((typ, body[p:p + size])); p += size
    return body[:prefix_end], extensions

def _encode_hello(prefix: bytes, extensions: Iterable[tuple[int, bytes]]) -> bytes:
    ext_blob = bytearray()
    for typ, payload in extensions:
        if len(payload) > 65535: raise ClientHelloError("extension too large")
        ext_blob += typ.to_bytes(2, "big") + len(payload).to_bytes(2, "big") + payload
    if len(ext_blob) > 65535: raise ClientHelloError("extension block too large")
    body = prefix + len(ext_blob).to_bytes(2, "big") + bytes(ext_blob)
    return b"\x01" + len(body).to_bytes(3, "big") + body

@dataclass
class Candidate:
    name: str
    wire: bytes
    note: str

def make_client_hello(server_name: str) -> bytes:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = context.wrap_bio(incoming, outgoing, server_side=False, server_hostname=server_name)
    try: client.do_handshake()
    except ssl.SSLWantReadError: pass
    wire = outgoing.read()
    if not wire: raise ClientHelloError("TLS backend did not emit a ClientHello")
    return wire

def generate_candidates(client_hello_wire: bytes) -> list[Candidate]:
    version, handshake = _extract_client_hello(client_hello_wire)
    candidates = [Candidate("baseline", _record(22, version, handshake), "unmodified ClientHello")]
    split_points = sorted({1, 4, 9, max(1, len(handshake) // 2), len(handshake) - 1})
    for point in split_points:
        if 0 < point < len(handshake):
            candidates.append(Candidate(f"record-split-{point}",
                _record(22, version, handshake[:point]) + _record(22, version, handshake[point:]),
                f"same handshake bytes split at byte {point}"))
    prefix, extensions = _hello_parts(handshake)
    if len(extensions) >= 2:
        candidates.append(Candidate("extensions-reversed",
            _record(22, version, _encode_hello(prefix, reversed(extensions))),
            "reverse extension order; first-flight probe only"))
        if any(t == 0 for t, _ in extensions):
            sni = [e for e in extensions if e[0] == 0]
            other = [e for e in extensions if e[0] != 0]
            candidates.append(Candidate("sni-first", _record(22, version, _encode_hello(prefix, sni + other)),
                                         "move SNI extension to first position"))
            candidates.append(Candidate("sni-last", _record(22, version, _encode_hello(prefix, other + sni)),
                                         "move SNI extension to last position"))
    if not any(t == 21 for t, _ in extensions):
        for size in (32, 128):
            candidates.append(Candidate(f"padding-{size}",
                _record(22, version, _encode_hello(prefix, list(extensions) + [(21, bytes(size))])),
                f"append TLS padding extension ({size} zero bytes)"))
    return candidates

def classify_response(data: bytes) -> str:
    if not data: return "empty"
    if len(data) >= 5 and data[0] in (20, 21, 22, 23):
        return {20: "change-cipher-spec", 21: "tls-alert", 22: "tls-handshake", 23: "tls-application-data"}[data[0]]
    return "non-tls-response"

@dataclass
class ProbeResult:
    candidate: str
    outcome: str
    elapsed_ms: float
    response_bytes: int
    response_prefix_hex: str
    note: str

def probe(host: str, port: int, candidate: Candidate, timeout: float) -> ProbeResult:
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout); sock.sendall(candidate.wire); response = sock.recv(4096)
        return ProbeResult(candidate.name, classify_response(response),
            round((time.monotonic() - start) * 1000, 2), len(response), response[:48].hex(), candidate.note)
    except socket.timeout:
        outcome, detail = "timeout", ""
    except ConnectionResetError:
        outcome, detail = "reset", ""
    except OSError as exc:
        outcome, detail = f"socket-error:{type(exc).__name__}", str(exc)
    return ProbeResult(candidate.name, outcome, round((time.monotonic() - start) * 1000, 2), 0, "",
                       candidate.note + ("; " + detail if detail else ""))

def main() -> int:
    parser = argparse.ArgumentParser(description="Probe TLS ClientHello variants against a controlled endpoint.")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--sni", required=True)
    parser.add_argument("--timeout", type=float, default=4.0)
    parser.add_argument("--json", dest="json_path", type=Path)
    parser.add_argument("--csv", dest="csv_path", type=Path)
    parser.add_argument("--ack-authorized", action="store_true",
                        help="confirm you own or are authorized to test this endpoint")
    args = parser.parse_args()
    if not args.ack_authorized:
        parser.error("test only endpoints you own or are authorized to assess; pass --ack-authorized")
    try:
        candidates = generate_candidates(make_client_hello(args.sni))
    except (ClientHelloError, ssl.SSLError) as exc:
        print(f"ClientHello generation failed: {exc}", file=sys.stderr); return 2
    print(f"Generated {len(candidates)} candidates; probing {args.host}:{args.port} (SNI={args.sni})")
    results = []
    for candidate in candidates:
        result = probe(args.host, args.port, candidate, args.timeout)
        results.append(asdict(result))
        print(f"{result.candidate:24} {result.outcome:22} {result.elapsed_ms:8.2f} ms")
    if args.json_path:
        args.json_path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    if args.csv_path:
        with args.csv_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(results[0])); writer.writeheader(); writer.writerows(results)
    print("NOTE: first-flight screening only; not a completed TLS handshake or proof of censorship bypass.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
