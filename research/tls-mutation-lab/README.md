# TLS mutation lab (research prototype)

This directory contains an isolated, standard-library-only prototype for repeatable TLS
ClientHello first-flight experiments. It is research tooling, not an Xray runtime feature.

## Current scope

The first iteration generates candidates from a real ClientHello produced by Python's TLS
implementation and probes a controlled, authorized TCP/TLS endpoint:

- baseline ClientHello;
- TLS record-layer splits at deterministic byte offsets (handshake bytes are preserved);
- extension-order variants (reverse, SNI first, SNI last);
- optional TLS padding extension sizes.

It records the first server response, elapsed time, response size and a short hex prefix as JSON
and/or CSV. Candidate order is deterministic so runs can be compared.

## Important interpretation limits

- A response classified as tls-handshake means the server emitted a TLS handshake record. It does
  not prove a complete TLS handshake or application connection would succeed.
- Extension reordering and padding alter the ClientHello transcript. This prototype intentionally
  stops after first-flight screening; it does not continue the TLS handshake with a mismatched
  local TLS transcript.
- Timeout, reset, and empty response are ambiguous. They may reflect server policy, middleboxes,
  routing, rate limiting, or transient network failure. They are not automatically scored as
  censorship.
- This first iteration is TCP/TLS only. QUIC is a separate phase because the Xray fork pins
  apernet/quic-go; QUIC Initial/CRYPTO framing must be inspected and tested against that exact
  dependency before adding a QUIC mutator.
- No candidate is sent to a public or third-party host by default. The operator must explicitly
  pass --ack-authorized.

## Run

Python 3.10+; no third-party packages:

    python3 tls_mutation_lab.py --host 127.0.0.1 --port 4433 --sni test.example \
      --ack-authorized --json run.json --csv run.csv

Use a local TLS test server or a server you own/control.

Run unit tests:

    python3 -m unittest -v

## Next engineering steps

1. Add controlled server-side capture/telemetry so client outcomes can be paired with server logs.
2. Add repeat runs, randomized candidate order, baseline interleaving, and confidence intervals;
   do not rank one-off timeouts as wins.
3. Add an evaluator interface for a locally deployed OpenGFW instance or another controlled test
   network. Keep it pluggable rather than hard-coding a censorship claim.
4. Inspect the exact pinned quic-go source and add QUIC candidates only after confirming packet
   construction, CRYPTO frame behavior, and interoperability.
5. Promote only repeatably successful, protocol-valid candidates into a separately reviewed Xray
   implementation. Do not couple this prototype to AndroidLibXrayLite or PattNG yet.

## Safety and project boundary

This tool is for protocol interoperability and controlled network measurement. Do not probe systems
without authorization. It does not change Xray production code, configuration, OOB path,
dependencies, or Android packaging.
