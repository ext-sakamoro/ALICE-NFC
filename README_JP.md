[English](README.md) | **日本語**

# ALICE-NFC

**ALICE NFCライブラリ** — NDEF、タグタイプ1-4、APDUコマンド、カードエミュレーション、アンチコリジョン、TLVエンコーディングをカバーする純Rust NFC実装。

[Project A.L.I.C.E.](https://github.com/anthropics/alice) エコシステムの一部。

## 機能

- **NDEFレコード** — Text、URI、MIME、Smart Posterレコードタイプ
- **タグタイプ1-4** — NFC Forumタグタイプの読み書き対応
- **APDUコマンド** — SELECT、READ BINARY、UPDATE BINARYの構築・パース
- **カードエミュレーション** — ホストカードエミュレーション（HCE）対応
- **アンチコリジョン** — 複数タグ衝突解決プロトコル
- **UID処理** — 4、7、10バイトUID対応（BCC計算付き）
- **TLVエンコーディング** — Tag-Length-Valueデータ構造のエンコード/デコード
- **No-std互換** — コア型は`core`のみ使用（ヒープ割り当て不要）

## アーキテクチャ

```
Uid（4 / 7 / 10バイト）
 ├── as_bytes()
 └── bcc()（XORチェックサム）

NDEF
 ├── NdefRecord（TNF、タイプ、ペイロード）
 ├── NdefMessage（順序付きレコード群）
 └── レコード種別: Text, URI, MIME, SmartPoster

APDU
 ├── SELECT（AID選択）
 ├── READ BINARY
 └── UPDATE BINARY

TagType
 ├── Type1（Topaz）
 ├── Type2（NTAG、Mifare Ultralight）
 ├── Type3（FeliCa）
 └── Type4（ISO-DEP）

AntiCollision
 └── 複数タグ解決

TLV
 └── エンコード / デコード
```

## クイックスタート

```rust
use alice_nfc::{Uid, NfcError};

let uid = Uid::new(&[0x04, 0xA2, 0xB3, 0xC4, 0xD5, 0xE6, 0xF7]).unwrap();
assert_eq!(uid.len(), 7);
let checksum = uid.bcc();
```

## ライセンス

MIT OR Apache-2.0
