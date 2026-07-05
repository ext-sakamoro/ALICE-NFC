//! Integration tests.

#![allow(
    clippy::wildcard_imports,
    clippy::too_many_lines,
    clippy::float_cmp,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use crate::anticollision::*;
use crate::apdu::*;
use crate::card_emulation::*;
use crate::errors::*;
use crate::ndef::*;
use crate::ndef::{FLAG_IL, FLAG_SR};
use crate::tag_types::*;
use crate::tlv::*;
use crate::uid::*;

use super::*;

// === UID tests ===

#[test]
fn uid_4byte() {
    let uid = Uid::new(&[0x01, 0x02, 0x03, 0x04]).unwrap();
    assert_eq!(uid.len(), 4);
    assert!(!uid.is_empty());
}

#[test]
fn uid_7byte() {
    let uid = Uid::new(&[1, 2, 3, 4, 5, 6, 7]).unwrap();
    assert_eq!(uid.len(), 7);
}

#[test]
fn uid_10byte() {
    let uid = Uid::new(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]).unwrap();
    assert_eq!(uid.len(), 10);
}

#[test]
fn uid_invalid_length() {
    assert!(Uid::new(&[1, 2, 3]).is_err());
    assert!(Uid::new(&[1, 2, 3, 4, 5]).is_err());
    assert!(Uid::new(&[]).is_err());
}

#[test]
fn uid_bcc() {
    let uid = Uid::new(&[0x01, 0x02, 0x03, 0x04]).unwrap();
    assert_eq!(uid.bcc(), 0x01 ^ 0x02 ^ 0x03 ^ 0x04);
}

#[test]
fn uid_display() {
    let uid = Uid::new(&[0xAB, 0xCD, 0xEF, 0x01]).unwrap();
    assert_eq!(format!("{uid}"), "AB:CD:EF:01");
}

#[test]
fn uid_as_bytes() {
    let uid = Uid::new(&[0x10, 0x20, 0x30, 0x40]).unwrap();
    assert_eq!(uid.as_bytes(), &[0x10, 0x20, 0x30, 0x40]);
}

// === TLV tests ===

#[test]
fn tlv_null() {
    let tlv = Tlv::new(TLV_NULL, Vec::new());
    let encoded = tlv.encode();
    assert_eq!(encoded, &[0x00, 0x00]);
}

#[test]
fn tlv_short_value() {
    let tlv = Tlv::new(0x03, vec![0xAA, 0xBB]);
    let encoded = tlv.encode();
    assert_eq!(encoded, &[0x03, 0x02, 0xAA, 0xBB]);
}

#[test]
fn tlv_3byte_length() {
    let data = vec![0x42; 300];
    let tlv = Tlv::new(0x03, data.clone());
    let encoded = tlv.encode();
    assert_eq!(encoded[0], 0x03);
    assert_eq!(encoded[1], 0xFF);
    assert_eq!(encoded[2], 0x01); // 300 >> 8
    assert_eq!(encoded[3], 0x2C); // 300 & 0xFF
    assert_eq!(&encoded[4..], &data[..]);
}

#[test]
fn tlv_parse_empty() {
    let data = [TLV_TERMINATOR];
    let tlvs = Tlv::parse_all(&data).unwrap();
    assert_eq!(tlvs.len(), 1);
    assert_eq!(tlvs[0].tag, TLV_TERMINATOR);
}

#[test]
fn tlv_parse_null_and_terminator() {
    let data = [TLV_NULL, TLV_TERMINATOR];
    let tlvs = Tlv::parse_all(&data).unwrap();
    assert_eq!(tlvs.len(), 2);
}

#[test]
fn tlv_parse_ndef() {
    let inner = vec![0xD1, 0x01, 0x00];
    let mut data = vec![0x03, 0x03]; // tag=NDEF, len=3
    data.extend_from_slice(&inner);
    data.push(TLV_TERMINATOR);
    let tlvs = Tlv::parse_all(&data).unwrap();
    assert_eq!(tlvs.len(), 2);
    assert_eq!(tlvs[0].tag, TLV_NDEF_MESSAGE);
    assert_eq!(tlvs[0].value, inner);
}

#[test]
fn tlv_roundtrip() {
    let original = Tlv::new(0xFD, vec![1, 2, 3, 4, 5]);
    let encoded = original.encode();
    let parsed = Tlv::parse_all(&encoded).unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0], original);
}

#[test]
fn tlv_parse_truncated() {
    assert!(Tlv::parse_all(&[0x03]).is_err());
}

#[test]
fn tlv_parse_3byte_len_truncated() {
    assert!(Tlv::parse_all(&[0x03, 0xFF, 0x00]).is_err());
}

#[test]
fn tlv_parse_value_too_short() {
    assert!(Tlv::parse_all(&[0x03, 0x05, 0x01]).is_err());
}

// === NDEF Record tests ===

#[test]
fn ndef_text_record() {
    let rec = NdefRecord::text("Hello");
    assert_eq!(rec.tnf, Tnf::WellKnown);
    assert_eq!(rec.record_type, vec![b'T']);
    let content = rec.text_content().unwrap();
    assert_eq!(content, "Hello");
}

#[test]
fn ndef_uri_record() {
    let rec = NdefRecord::uri(0x04, "example.com");
    let content = rec.uri_content().unwrap();
    assert_eq!(content, "https://example.com");
}

#[test]
fn ndef_uri_prefix_http() {
    assert_eq!(uri_prefix(0x03), "http://");
}

#[test]
fn ndef_uri_prefix_unknown() {
    assert_eq!(uri_prefix(0xFF), "");
}

#[test]
fn ndef_uri_prefix_tel() {
    assert_eq!(uri_prefix(0x05), "tel:");
}

#[test]
fn ndef_uri_prefix_mailto() {
    assert_eq!(uri_prefix(0x06), "mailto:");
}

#[test]
fn ndef_mime_record() {
    let rec = NdefRecord::mime("text/plain", b"test data");
    assert_eq!(rec.tnf, Tnf::MimeMedia);
    assert_eq!(rec.record_type, b"text/plain");
    assert_eq!(rec.payload, b"test data");
}

#[test]
fn ndef_smart_poster() {
    let uri = NdefRecord::uri(0x04, "example.com");
    let title = NdefRecord::text("Example");
    let sp = NdefRecord::smart_poster(&[uri, title]);
    assert_eq!(sp.tnf, Tnf::WellKnown);
    assert_eq!(sp.record_type, b"Sp");
}

#[test]
fn ndef_record_encode_single() {
    let rec = NdefRecord::text("Hi");
    let bytes = rec.encode(true, true);
    // flags: MB|ME|SR|TNF=1 => 0x80|0x40|0x10|0x01 = 0xD1
    assert_eq!(bytes[0], 0xD1);
    assert_eq!(bytes[1], 1); // type length
}

#[test]
fn ndef_record_parse_roundtrip() {
    let rec = NdefRecord::text("Roundtrip");
    let bytes = rec.encode(true, true);
    let (parsed, consumed) = NdefRecord::parse(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(parsed.payload, rec.payload);
}

#[test]
fn ndef_record_with_id() {
    let rec = NdefRecord::new(
        Tnf::WellKnown,
        vec![b'T'],
        vec![0x01],
        vec![0x02, b'e', b'n', b'X'],
    );
    let bytes = rec.encode(true, true);
    assert!(bytes[0] & FLAG_IL != 0);
    let (parsed, _) = NdefRecord::parse(&bytes).unwrap();
    assert_eq!(parsed.id, vec![0x01]);
}

#[test]
fn ndef_record_long_payload() {
    let payload = vec![0x42; 300];
    let rec = NdefRecord::new(Tnf::Unknown, Vec::new(), Vec::new(), payload.clone());
    let bytes = rec.encode(true, true);
    assert!(bytes[0] & FLAG_SR == 0); // not short record
    let (parsed, _) = NdefRecord::parse(&bytes).unwrap();
    assert_eq!(parsed.payload, payload);
}

#[test]
fn ndef_text_content_invalid() {
    let rec = NdefRecord::uri(0x00, "test");
    assert!(rec.text_content().is_err());
}

#[test]
fn ndef_uri_content_invalid() {
    let rec = NdefRecord::text("test");
    assert!(rec.uri_content().is_err());
}

#[test]
fn ndef_text_empty_payload() {
    let rec = NdefRecord::new(Tnf::WellKnown, vec![b'T'], Vec::new(), Vec::new());
    assert!(rec.text_content().is_err());
}

#[test]
fn ndef_parse_empty_data() {
    assert!(NdefRecord::parse(&[]).is_err());
}

#[test]
fn ndef_parse_truncated_type_len() {
    assert!(NdefRecord::parse(&[0xD1]).is_err());
}

// === NDEF Message tests ===

#[test]
fn ndef_message_single_record() {
    let msg = NdefMessage::new(vec![NdefRecord::text("Test")]);
    let bytes = msg.encode();
    let parsed = NdefMessage::parse(&bytes).unwrap();
    assert_eq!(parsed.records.len(), 1);
}

#[test]
fn ndef_message_multiple_records() {
    let msg = NdefMessage::new(vec![
        NdefRecord::text("One"),
        NdefRecord::uri(0x04, "example.com"),
        NdefRecord::text("Three"),
    ]);
    let bytes = msg.encode();
    let parsed = NdefMessage::parse(&bytes).unwrap();
    assert_eq!(parsed.records.len(), 3);
}

#[test]
fn ndef_message_to_tlv() {
    let msg = NdefMessage::new(vec![NdefRecord::text("TLV")]);
    let tlv_bytes = msg.to_tlv();
    assert_eq!(tlv_bytes[0], TLV_NDEF_MESSAGE);
    assert_eq!(*tlv_bytes.last().unwrap(), TLV_TERMINATOR);
}

#[test]
fn ndef_message_parse_empty() {
    assert!(NdefMessage::parse(&[]).is_err());
}

#[test]
fn ndef_message_roundtrip() {
    let original = NdefMessage::new(vec![
        NdefRecord::text("Hello"),
        NdefRecord::uri(0x01, "example.com"),
    ]);
    let bytes = original.encode();
    let parsed = NdefMessage::parse(&bytes).unwrap();
    assert_eq!(parsed.records.len(), 2);
    assert_eq!(parsed.records[0].text_content().unwrap(), "Hello");
    assert_eq!(
        parsed.records[1].uri_content().unwrap(),
        "http://www.example.com"
    );
}

#[test]
fn ndef_smart_poster_roundtrip() {
    let inner_uri = NdefRecord::uri(0x04, "rust-lang.org");
    let inner_text = NdefRecord::text("Rust");
    let sp = NdefRecord::smart_poster(&[inner_uri, inner_text]);
    let msg = NdefMessage::new(vec![sp]);
    let bytes = msg.encode();
    let parsed = NdefMessage::parse(&bytes).unwrap();
    assert_eq!(parsed.records.len(), 1);
    assert_eq!(parsed.records[0].record_type, b"Sp");
    // Parse inner message
    let inner = NdefMessage::parse(&parsed.records[0].payload).unwrap();
    assert_eq!(inner.records.len(), 2);
}

// === TNF tests ===

#[test]
fn tnf_from_byte_all() {
    assert_eq!(Tnf::from_byte(0x00), Tnf::Empty);
    assert_eq!(Tnf::from_byte(0x01), Tnf::WellKnown);
    assert_eq!(Tnf::from_byte(0x02), Tnf::MimeMedia);
    assert_eq!(Tnf::from_byte(0x03), Tnf::AbsoluteUri);
    assert_eq!(Tnf::from_byte(0x04), Tnf::External);
    assert_eq!(Tnf::from_byte(0x05), Tnf::Unknown);
    assert_eq!(Tnf::from_byte(0x06), Tnf::Unchanged);
    assert_eq!(Tnf::from_byte(0x07), Tnf::Reserved);
}

#[test]
fn tnf_from_byte_masked() {
    // Only bottom 3 bits matter
    assert_eq!(Tnf::from_byte(0xF1), Tnf::WellKnown);
    assert_eq!(Tnf::from_byte(0x88), Tnf::Empty);
}

// === APDU tests ===

#[test]
fn apdu_select() {
    let cmd = ApduCommand::select(NDEF_TAG_APPLICATION_AID);
    assert_eq!(cmd.ins, INS_SELECT);
    assert_eq!(cmd.p1, 0x04);
    assert_eq!(cmd.data, NDEF_TAG_APPLICATION_AID);
}

#[test]
fn apdu_read_binary() {
    let cmd = ApduCommand::read_binary(0x0000, 0x0F);
    assert_eq!(cmd.ins, INS_READ_BINARY);
    assert_eq!(cmd.p1, 0x00);
    assert_eq!(cmd.p2, 0x00);
    assert_eq!(cmd.le, Some(0x0F));
}

#[test]
fn apdu_update_binary() {
    let cmd = ApduCommand::update_binary(0x0004, &[0xAA, 0xBB]);
    assert_eq!(cmd.ins, INS_UPDATE_BINARY);
    assert_eq!(cmd.p1, 0x00);
    assert_eq!(cmd.p2, 0x04);
    assert_eq!(cmd.data, vec![0xAA, 0xBB]);
}

#[test]
fn apdu_read_binary_offset() {
    let cmd = ApduCommand::read_binary(0x0102, 16);
    assert_eq!(cmd.p1, 0x01);
    assert_eq!(cmd.p2, 0x02);
}

#[test]
fn apdu_encode_header_only() {
    let cmd = ApduCommand::new(0x00, 0xA4, 0x04, 0x00);
    let bytes = cmd.encode();
    assert_eq!(bytes, &[0x00, 0xA4, 0x04, 0x00]);
}

#[test]
fn apdu_encode_with_data() {
    let cmd = ApduCommand::new(0x00, 0xA4, 0x04, 0x00).with_data(vec![0x01, 0x02]);
    let bytes = cmd.encode();
    assert_eq!(bytes, &[0x00, 0xA4, 0x04, 0x00, 0x02, 0x01, 0x02]);
}

#[test]
fn apdu_encode_with_le() {
    let cmd = ApduCommand::new(0x00, 0xB0, 0x00, 0x00).with_le(0x10);
    let bytes = cmd.encode();
    assert_eq!(bytes, &[0x00, 0xB0, 0x00, 0x00, 0x10]);
}

#[test]
fn apdu_encode_with_data_and_le() {
    let cmd = ApduCommand::new(0x00, 0xA4, 0x04, 0x00)
        .with_data(vec![0xAA])
        .with_le(0x00);
    let bytes = cmd.encode();
    assert_eq!(bytes, &[0x00, 0xA4, 0x04, 0x00, 0x01, 0xAA, 0x00]);
}

#[test]
fn apdu_parse_header_only() {
    let cmd = ApduCommand::parse(&[0x00, 0xA4, 0x04, 0x00]).unwrap();
    assert_eq!(cmd.cla, 0x00);
    assert_eq!(cmd.ins, 0xA4);
    assert!(cmd.data.is_empty());
    assert!(cmd.le.is_none());
}

#[test]
fn apdu_parse_le_only() {
    let cmd = ApduCommand::parse(&[0x00, 0xB0, 0x00, 0x00, 0x10]).unwrap();
    assert_eq!(cmd.le, Some(0x10));
    assert!(cmd.data.is_empty());
}

#[test]
fn apdu_parse_with_data() {
    let cmd = ApduCommand::parse(&[0x00, 0xA4, 0x04, 0x00, 0x02, 0xAA, 0xBB]).unwrap();
    assert_eq!(cmd.data, vec![0xAA, 0xBB]);
}

#[test]
fn apdu_parse_data_and_le() {
    let cmd = ApduCommand::parse(&[0x00, 0xA4, 0x04, 0x00, 0x01, 0xAA, 0x10]).unwrap();
    assert_eq!(cmd.data, vec![0xAA]);
    assert_eq!(cmd.le, Some(0x10));
}

#[test]
fn apdu_parse_too_short() {
    assert!(ApduCommand::parse(&[0x00, 0xA4]).is_err());
}

#[test]
fn apdu_parse_lc_overflow() {
    assert!(ApduCommand::parse(&[0x00, 0xA4, 0x00, 0x00, 0x05, 0x01]).is_err());
}

#[test]
fn apdu_roundtrip() {
    let original = ApduCommand::select(&[0xD2, 0x76]);
    let bytes = original.encode();
    let parsed = ApduCommand::parse(&bytes).unwrap();
    assert_eq!(parsed.ins, original.ins);
    assert_eq!(parsed.data, original.data);
}

// === APDU Response tests ===

#[test]
fn apdu_response_success() {
    let resp = ApduResponse::success(vec![0x01, 0x02]);
    assert!(resp.is_ok());
    assert_eq!(resp.status_word(), 0x9000);
}

#[test]
fn apdu_response_error() {
    let resp = ApduResponse::error(0x6A, 0x82);
    assert!(!resp.is_ok());
    assert_eq!(resp.status_word(), 0x6A82);
}

#[test]
fn apdu_response_encode() {
    let resp = ApduResponse::success(vec![0xAA]);
    let bytes = resp.encode();
    assert_eq!(bytes, &[0xAA, 0x90, 0x00]);
}

#[test]
fn apdu_response_parse() {
    let resp = ApduResponse::parse(&[0xAA, 0xBB, 0x90, 0x00]).unwrap();
    assert_eq!(resp.data, vec![0xAA, 0xBB]);
    assert!(resp.is_ok());
}

#[test]
fn apdu_response_parse_sw_only() {
    let resp = ApduResponse::parse(&[0x90, 0x00]).unwrap();
    assert!(resp.data.is_empty());
    assert!(resp.is_ok());
}

#[test]
fn apdu_response_parse_too_short() {
    assert!(ApduResponse::parse(&[0x90]).is_err());
}

// === Tag tests ===

#[test]
fn tag_type1_create() {
    let uid = Uid::new(&[1, 2, 3, 4]).unwrap();
    let tag = Tag::new(TagType::Type1, uid, 120);
    assert_eq!(tag.tag_type, TagType::Type1);
    assert_eq!(tag.capacity(), 120);
    assert!(!tag.is_read_only());
}

#[test]
fn tag_read_write() {
    let uid = Uid::new(&[1, 2, 3, 4]).unwrap();
    let mut tag = Tag::new(TagType::Type2, uid, 64);
    tag.write(0, &[0xAA, 0xBB]).unwrap();
    assert_eq!(tag.read(0, 2).unwrap(), &[0xAA, 0xBB]);
}

#[test]
fn tag_read_out_of_range() {
    let uid = Uid::new(&[1, 2, 3, 4]).unwrap();
    let tag = Tag::new(TagType::Type1, uid, 16);
    assert!(tag.read(15, 4).is_err());
}

#[test]
fn tag_write_out_of_range() {
    let uid = Uid::new(&[1, 2, 3, 4]).unwrap();
    let mut tag = Tag::new(TagType::Type1, uid, 16);
    assert!(tag.write(15, &[1, 2, 3]).is_err());
}

#[test]
fn tag_read_only() {
    let uid = Uid::new(&[1, 2, 3, 4]).unwrap();
    let mut tag = Tag::new(TagType::Type2, uid, 64);
    tag.set_read_only();
    assert!(tag.is_read_only());
    assert!(tag.write(0, &[0xFF]).is_err());
}

#[test]
fn tag_write_read_ndef_type1() {
    let uid = Uid::new(&[1, 2, 3, 4]).unwrap();
    let mut tag = Tag::new(TagType::Type1, uid, 256);
    let msg = NdefMessage::new(vec![NdefRecord::text("Tag1")]);
    tag.write_ndef(&msg).unwrap();
    let read = tag.read_ndef().unwrap();
    assert_eq!(read.records[0].text_content().unwrap(), "Tag1");
}

#[test]
fn tag_write_read_ndef_type2() {
    let uid = Uid::new(&[1, 2, 3, 4]).unwrap();
    let mut tag = Tag::new(TagType::Type2, uid, 256);
    let msg = NdefMessage::new(vec![NdefRecord::uri(0x04, "rust-lang.org")]);
    tag.write_ndef(&msg).unwrap();
    let read = tag.read_ndef().unwrap();
    assert_eq!(
        read.records[0].uri_content().unwrap(),
        "https://rust-lang.org"
    );
}

#[test]
fn tag_write_read_ndef_type3() {
    let uid = Uid::new(&[1, 2, 3, 4]).unwrap();
    let mut tag = Tag::new(TagType::Type3, uid, 256);
    let msg = NdefMessage::new(vec![NdefRecord::text("Tag3")]);
    tag.write_ndef(&msg).unwrap();
    let read = tag.read_ndef().unwrap();
    assert_eq!(read.records[0].text_content().unwrap(), "Tag3");
}

#[test]
fn tag_write_read_ndef_type4() {
    let uid = Uid::new(&[1, 2, 3, 4]).unwrap();
    let mut tag = Tag::new(TagType::Type4, uid, 256);
    let msg = NdefMessage::new(vec![NdefRecord::text("Tag4")]);
    tag.write_ndef(&msg).unwrap();
    let read = tag.read_ndef().unwrap();
    assert_eq!(read.records[0].text_content().unwrap(), "Tag4");
}

#[test]
fn tag_ndef_too_large() {
    let uid = Uid::new(&[1, 2, 3, 4]).unwrap();
    let mut tag = Tag::new(TagType::Type2, uid, 20);
    let msg = NdefMessage::new(vec![NdefRecord::text(
        "This is way too long for a tiny tag",
    )]);
    assert!(tag.write_ndef(&msg).is_err());
}

#[test]
fn tag_no_ndef() {
    let uid = Uid::new(&[1, 2, 3, 4]).unwrap();
    let tag = Tag::new(TagType::Type2, uid, 256);
    assert!(tag.read_ndef().is_err());
}

// === Anti-collision tests ===

#[test]
fn anticollision_default() {
    let ac = AntiCollision::new();
    assert_eq!(ac.cascade_level(), CascadeLevel::Level1);
}

#[test]
fn anticollision_cmd_level1() {
    let ac = AntiCollision::new();
    let cmd = ac.build_anticollision_cmd();
    assert_eq!(cmd[0], 0x93);
    assert_eq!(cmd[1], 0x20);
}

#[test]
fn anticollision_advance() {
    let mut ac = AntiCollision::new();
    ac.advance();
    assert_eq!(ac.cascade_level(), CascadeLevel::Level2);
    let cmd = ac.build_anticollision_cmd();
    assert_eq!(cmd[0], 0x95);
}

#[test]
fn anticollision_advance_to_level3() {
    let mut ac = AntiCollision::new();
    ac.advance();
    ac.advance();
    assert_eq!(ac.cascade_level(), CascadeLevel::Level3);
    assert_eq!(ac.cascade_level().sel_byte(), 0x97);
}

#[test]
fn anticollision_advance_beyond_level3() {
    let mut ac = AntiCollision::new();
    ac.advance();
    ac.advance();
    ac.advance();
    assert_eq!(ac.cascade_level(), CascadeLevel::Level3);
}

#[test]
fn anticollision_set_partial() {
    let mut ac = AntiCollision::new();
    ac.set_partial(2, &[0xAA, 0xBB]);
    let cmd = ac.build_anticollision_cmd();
    assert_eq!(cmd[1], 0x22); // 0x20 + 2
    assert_eq!(&cmd[2..], &[0xAA, 0xBB]);
}

#[test]
fn anticollision_select_cmd() {
    let ac = AntiCollision::new();
    let cmd = ac.build_select_cmd(&[0x01, 0x02, 0x03, 0x04], 0x04);
    assert_eq!(cmd[0], 0x93);
    assert_eq!(cmd[1], 0x70);
    assert_eq!(&cmd[2..6], &[0x01, 0x02, 0x03, 0x04]);
    assert_eq!(cmd[6], 0x04);
}

#[test]
fn resolve_uid_4byte() {
    let uid = AntiCollision::resolve_uid(&[0x01, 0x02, 0x03, 0x04], None, None).unwrap();
    assert_eq!(uid.len(), 4);
    assert_eq!(uid.as_bytes(), &[0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn resolve_uid_7byte() {
    let uid = AntiCollision::resolve_uid(
        &[CASCADE_TAG, 0x01, 0x02, 0x03],
        Some(&[0x04, 0x05, 0x06, 0x07]),
        None,
    )
    .unwrap();
    assert_eq!(uid.len(), 7);
    assert_eq!(uid.as_bytes(), &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
}

#[test]
fn resolve_uid_10byte() {
    let uid = AntiCollision::resolve_uid(
        &[CASCADE_TAG, 0x01, 0x02, 0x03],
        Some(&[CASCADE_TAG, 0x04, 0x05, 0x06]),
        Some(&[0x07, 0x08, 0x09, 0x0A]),
    )
    .unwrap();
    assert_eq!(uid.len(), 10);
}

#[test]
fn resolve_uid_bad_cl1() {
    assert!(AntiCollision::resolve_uid(&[0x01, 0x02], None, None).is_err());
}

#[test]
fn resolve_uid_cl3_without_cl2() {
    assert!(
        AntiCollision::resolve_uid(&[0x01, 0x02, 0x03, 0x04], None, Some(&[1, 2, 3, 4])).is_err()
    );
}

#[test]
fn resolve_uid_bad_cl2_len() {
    assert!(AntiCollision::resolve_uid(&[CASCADE_TAG, 1, 2, 3], Some(&[1, 2]), None).is_err());
}

#[test]
fn cascade_tag_value() {
    assert_eq!(CASCADE_TAG, 0x88);
}

// === Card Emulation tests ===

#[test]
fn card_emu_select_aid() {
    let msg = NdefMessage::new(vec![NdefRecord::text("Card")]);
    let mut emu = CardEmulator::new(&msg);
    let cmd = ApduCommand::select(NDEF_TAG_APPLICATION_AID);
    let resp = emu.process(&cmd);
    assert!(resp.is_ok());
}

#[test]
fn card_emu_select_wrong_aid() {
    let msg = NdefMessage::new(vec![NdefRecord::text("Card")]);
    let mut emu = CardEmulator::new(&msg);
    let cmd = ApduCommand::select(&[0x00, 0x01]);
    let resp = emu.process(&cmd);
    assert!(!resp.is_ok());
    assert_eq!(resp.status_word(), 0x6A82);
}

#[test]
fn card_emu_select_cc_file() {
    let msg = NdefMessage::new(vec![NdefRecord::text("CC")]);
    let mut emu = CardEmulator::new(&msg);
    // Select app first
    let _ = emu.process(&ApduCommand::select(NDEF_TAG_APPLICATION_AID));
    // Select CC file
    let cmd = ApduCommand::new(0x00, INS_SELECT, 0x00, 0x00).with_data(vec![0xE1, 0x03]);
    let resp = emu.process(&cmd);
    assert!(resp.is_ok());
}

#[test]
fn card_emu_select_ndef_file() {
    let msg = NdefMessage::new(vec![NdefRecord::text("NDEF")]);
    let mut emu = CardEmulator::new(&msg);
    let _ = emu.process(&ApduCommand::select(NDEF_TAG_APPLICATION_AID));
    let cmd = ApduCommand::new(0x00, INS_SELECT, 0x00, 0x00).with_data(vec![0xE1, 0x04]);
    let resp = emu.process(&cmd);
    assert!(resp.is_ok());
}

#[test]
fn card_emu_select_file_without_app() {
    let msg = NdefMessage::new(vec![NdefRecord::text("X")]);
    let mut emu = CardEmulator::new(&msg);
    let cmd = ApduCommand::new(0x00, INS_SELECT, 0x00, 0x00).with_data(vec![0xE1, 0x03]);
    let resp = emu.process(&cmd);
    assert!(!resp.is_ok());
}

#[test]
fn card_emu_read_cc() {
    let msg = NdefMessage::new(vec![NdefRecord::text("R")]);
    let mut emu = CardEmulator::new(&msg);
    let _ = emu.process(&ApduCommand::select(NDEF_TAG_APPLICATION_AID));
    let _ =
        emu.process(&ApduCommand::new(0x00, INS_SELECT, 0x00, 0x00).with_data(vec![0xE1, 0x03]));
    let read_cmd = ApduCommand::read_binary(0, 15);
    let resp = emu.process(&read_cmd);
    assert!(resp.is_ok());
    assert_eq!(resp.data.len(), 15);
    assert_eq!(resp.data[2], 0x20); // mapping version
}

#[test]
fn card_emu_read_ndef() {
    let msg = NdefMessage::new(vec![NdefRecord::text("ReadMe")]);
    let mut emu = CardEmulator::new(&msg);
    let _ = emu.process(&ApduCommand::select(NDEF_TAG_APPLICATION_AID));
    let _ =
        emu.process(&ApduCommand::new(0x00, INS_SELECT, 0x00, 0x00).with_data(vec![0xE1, 0x04]));
    // Read the first 2 bytes (NDEF length)
    let read_cmd = ApduCommand::read_binary(0, 2);
    let resp = emu.process(&read_cmd);
    assert!(resp.is_ok());
    assert_eq!(resp.data.len(), 2);
}

#[test]
fn card_emu_read_no_file_selected() {
    let msg = NdefMessage::new(vec![NdefRecord::text("X")]);
    let mut emu = CardEmulator::new(&msg);
    let _ = emu.process(&ApduCommand::select(NDEF_TAG_APPLICATION_AID));
    let resp = emu.process(&ApduCommand::read_binary(0, 4));
    assert!(!resp.is_ok());
}

#[test]
fn card_emu_update_ndef() {
    let msg = NdefMessage::new(vec![NdefRecord::text("Old")]);
    let mut emu = CardEmulator::new(&msg);
    let _ = emu.process(&ApduCommand::select(NDEF_TAG_APPLICATION_AID));
    let _ =
        emu.process(&ApduCommand::new(0x00, INS_SELECT, 0x00, 0x00).with_data(vec![0xE1, 0x04]));
    let new_msg = NdefMessage::new(vec![NdefRecord::text("New")]);
    let new_bytes = new_msg.encode();
    #[allow(clippy::cast_possible_truncation)]
    let len_prefix = vec![(new_bytes.len() >> 8) as u8, new_bytes.len() as u8];
    let update_len = ApduCommand::update_binary(0, &len_prefix);
    let resp = emu.process(&update_len);
    assert!(resp.is_ok());
    let update_data = ApduCommand::update_binary(2, &new_bytes);
    let resp = emu.process(&update_data);
    assert!(resp.is_ok());
    let read_msg = emu.ndef_message().unwrap();
    assert_eq!(read_msg.records[0].text_content().unwrap(), "New");
}

#[test]
fn card_emu_update_cc_denied() {
    let msg = NdefMessage::new(vec![NdefRecord::text("X")]);
    let mut emu = CardEmulator::new(&msg);
    let _ = emu.process(&ApduCommand::select(NDEF_TAG_APPLICATION_AID));
    let _ =
        emu.process(&ApduCommand::new(0x00, INS_SELECT, 0x00, 0x00).with_data(vec![0xE1, 0x03]));
    let resp = emu.process(&ApduCommand::update_binary(0, &[0xFF]));
    assert!(!resp.is_ok());
}

#[test]
fn card_emu_unsupported_ins() {
    let msg = NdefMessage::new(vec![NdefRecord::text("X")]);
    let mut emu = CardEmulator::new(&msg);
    let cmd = ApduCommand::new(0x00, 0xFF, 0x00, 0x00);
    let resp = emu.process(&cmd);
    assert_eq!(resp.status_word(), 0x6D00);
}

#[test]
fn card_emu_ndef_message_getter() {
    let msg = NdefMessage::new(vec![NdefRecord::uri(0x04, "nfc.example.com")]);
    let emu = CardEmulator::new(&msg);
    let retrieved = emu.ndef_message().unwrap();
    assert_eq!(
        retrieved.records[0].uri_content().unwrap(),
        "https://nfc.example.com"
    );
}

#[test]
fn card_emu_bad_select_p1() {
    let msg = NdefMessage::new(vec![NdefRecord::text("X")]);
    let mut emu = CardEmulator::new(&msg);
    let cmd = ApduCommand::new(0x00, INS_SELECT, 0x08, 0x00);
    let resp = emu.process(&cmd);
    assert!(!resp.is_ok());
}

#[test]
fn card_emu_select_invalid_file_id() {
    let msg = NdefMessage::new(vec![NdefRecord::text("X")]);
    let mut emu = CardEmulator::new(&msg);
    let _ = emu.process(&ApduCommand::select(NDEF_TAG_APPLICATION_AID));
    let cmd = ApduCommand::new(0x00, INS_SELECT, 0x00, 0x00).with_data(vec![0xFF, 0xFF]);
    let resp = emu.process(&cmd);
    assert_eq!(resp.status_word(), 0x6A82);
}

#[test]
fn card_emu_read_past_end() {
    let msg = NdefMessage::new(vec![NdefRecord::text("X")]);
    let mut emu = CardEmulator::new(&msg);
    let _ = emu.process(&ApduCommand::select(NDEF_TAG_APPLICATION_AID));
    let _ =
        emu.process(&ApduCommand::new(0x00, INS_SELECT, 0x00, 0x00).with_data(vec![0xE1, 0x03]));
    let read_cmd = ApduCommand::read_binary(0xFF00, 1);
    let resp = emu.process(&read_cmd);
    assert!(!resp.is_ok());
}

// === Error Display tests ===

#[test]
fn error_display() {
    let e = NfcError::InvalidPayload("bad");
    assert_eq!(format!("{e}"), "bad");
    let e2 = NfcError::BufferTooSmall;
    assert_eq!(format!("{e2}"), "buffer too small");
}

#[test]
fn error_display_all_variants() {
    assert!(!format!("{}", NfcError::InvalidNdef("x")).is_empty());
    assert!(!format!("{}", NfcError::InvalidTlv("x")).is_empty());
    assert!(!format!("{}", NfcError::InvalidApdu("x")).is_empty());
    assert!(!format!("{}", NfcError::TagError("x")).is_empty());
    assert!(!format!("{}", NfcError::CollisionError("x")).is_empty());
}

// === URI prefix coverage ===

#[test]
fn uri_prefixes_selected() {
    assert_eq!(uri_prefix(0x01), "http://www.");
    assert_eq!(uri_prefix(0x02), "https://www.");
    assert_eq!(uri_prefix(0x09), "ftps://");
    assert_eq!(uri_prefix(0x0A), "sftp://");
    assert_eq!(uri_prefix(0x0D), "ftp://");
    assert_eq!(uri_prefix(0x13), "urn:");
    assert_eq!(uri_prefix(0x1D), "file://");
    assert_eq!(uri_prefix(0x23), "urn:nfc:");
}

// === Additional edge-case tests ===

#[test]
fn ndef_message_encode_decode_five_records() {
    let records: Vec<NdefRecord> = (0..5)
        .map(|i| NdefRecord::text(&format!("Rec{i}")))
        .collect();
    let msg = NdefMessage::new(records);
    let bytes = msg.encode();
    let parsed = NdefMessage::parse(&bytes).unwrap();
    assert_eq!(parsed.records.len(), 5);
    for (i, rec) in parsed.records.iter().enumerate() {
        assert_eq!(rec.text_content().unwrap(), format!("Rec{i}"));
    }
}

#[test]
fn tag_type2_multiple_writes() {
    let uid = Uid::new(&[0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
    let mut tag = Tag::new(TagType::Type2, uid, 512);
    let msg1 = NdefMessage::new(vec![NdefRecord::text("First")]);
    tag.write_ndef(&msg1).unwrap();
    let msg2 = NdefMessage::new(vec![NdefRecord::text("Second")]);
    tag.write_ndef(&msg2).unwrap();
    let read = tag.read_ndef().unwrap();
    assert_eq!(read.records[0].text_content().unwrap(), "Second");
}

#[test]
fn uid_clone_eq() {
    let uid1 = Uid::new(&[1, 2, 3, 4]).unwrap();
    let uid2 = uid1.clone();
    assert_eq!(uid1, uid2);
}

#[test]
fn anticollision_default_trait() {
    let ac = AntiCollision::default();
    assert_eq!(ac.cascade_level(), CascadeLevel::Level1);
}
