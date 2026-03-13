**English** | [日本語](README_JP.md)

# ALICE-NFC

**ALICE NFC Library** — Pure Rust NFC implementation covering NDEF, Tag Types 1-4, APDU commands, card emulation, anti-collision, and TLV encoding.

Part of [Project A.L.I.C.E.](https://github.com/anthropics/alice) ecosystem.

## Features

- **NDEF Records** — Text, URI, MIME, and Smart Poster record types
- **Tag Types 1-4** — Read/write support for NFC Forum tag types
- **APDU Commands** — SELECT, READ BINARY, UPDATE BINARY command building/parsing
- **Card Emulation** — Host card emulation (HCE) support
- **Anti-Collision** — Multi-tag collision resolution protocol
- **UID Handling** — 4, 7, and 10-byte UID support with BCC computation
- **TLV Encoding** — Tag-Length-Value data structure encoding/decoding
- **No-std Compatible** — Core types use `core` only (no heap allocation required)

## Architecture

```
Uid (4 / 7 / 10 bytes)
 ├── as_bytes()
 └── bcc() (XOR checksum)

NDEF
 ├── NdefRecord (TNF, type, payload)
 ├── NdefMessage (ordered records)
 └── Record types: Text, URI, MIME, SmartPoster

APDU
 ├── SELECT (AID selection)
 ├── READ BINARY
 └── UPDATE BINARY

TagType
 ├── Type1 (Topaz)
 ├── Type2 (NTAG, Mifare Ultralight)
 ├── Type3 (FeliCa)
 └── Type4 (ISO-DEP)

AntiCollision
 └── Multi-tag resolution

TLV
 └── Encode / Decode
```

## Quick Start

```rust
use alice_nfc::{Uid, NfcError};

let uid = Uid::new(&[0x04, 0xA2, 0xB3, 0xC4, 0xD5, 0xE6, 0xF7]).unwrap();
assert_eq!(uid.len(), 7);
let checksum = uid.bcc();
```

## License

MIT OR Apache-2.0
