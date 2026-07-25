//// Unit tests for the pure crypto/encoding helpers in gleam_pds/crypto.
//// These cover the primitives that had bugs during development: the CID
//// codec (dag-cbor for records vs. raw for blobs) and JWT verification
//// (signature, expiry, tampering).

import gleam_pds/crypto
import gleam/json
import gleam/option.{Some}
import gleam/order
import gleam/string
import gleeunit/should

fn now_secs() -> Int {
  crypto.timestamp_microseconds() / 1_000_000
}

// ── CID codecs ───────────────────────────────────────────────────────────────

pub fn record_cid_uses_dagcbor_codec_test() {
  // Records are CIDv1 dag-cbor (0x71); base32 of that starts "bafyrei".
  crypto.compute_cid(<<"hello">>)
  |> string.starts_with("bafyrei")
  |> should.be_true
}

pub fn blob_cid_uses_raw_codec_test() {
  // AT Protocol requires blob refs to use the raw codec (0x55) -> "bafkrei".
  crypto.compute_blob_cid(<<"hello">>)
  |> string.starts_with("bafkrei")
  |> should.be_true
}

pub fn cid_is_deterministic_test() {
  should.equal(crypto.compute_cid(<<"abc">>), crypto.compute_cid(<<"abc">>))
}

pub fn record_and_blob_cid_differ_test() {
  // Same bytes, different codec => different CID string.
  should.not_equal(
    crypto.compute_cid(<<"x">>),
    crypto.compute_blob_cid(<<"x">>),
  )
}

// ── base32 / base64url ───────────────────────────────────────────────────────

pub fn base32_roundtrip_test() {
  let data = <<1, 2, 3, 250, 100, 0, 42>>
  let assert Ok(decoded) = crypto.base32_decode(crypto.base32_encode(data))
  should.equal(decoded, data)
}

pub fn base64url_roundtrip_test() {
  let data = <<255, 0, 128, 64, 32, 17>>
  let assert Ok(decoded) =
    crypto.base64url_decode(crypto.base64url_encode(data))
  should.equal(decoded, data)
}

// ── passwords ────────────────────────────────────────────────────────────────

pub fn password_hash_roundtrip_test() {
  let hash = crypto.hash_password("correct horse battery staple")
  should.be_true(crypto.verify_password("correct horse battery staple", hash))
  should.be_false(crypto.verify_password("wrong password", hash))
}

pub fn password_hash_is_salted_test() {
  // Random per-hash salt => the same password hashes to different values.
  should.not_equal(crypto.hash_password("samepw"), crypto.hash_password("samepw"))
}

// ── TID ──────────────────────────────────────────────────────────────────────

pub fn tid_format_test() {
  // AT Protocol TIDs are 13 base32-sortable characters.
  should.equal(string.length(crypto.generate_tid()), 13)
}

pub fn tid_is_sortable_test() {
  // A later TID never sorts before an earlier one. Compared with
  // string.compare, since Gleam's <= is Int-only.
  let a = crypto.generate_tid()
  let b = crypto.generate_tid()
  should.not_equal(string.compare(a, b), order.Gt)
}

// ── constant-time compare ────────────────────────────────────────────────────

pub fn secure_compare_test() {
  should.be_true(crypto.secure_compare(<<"abc">>, <<"abc">>))
  should.be_false(crypto.secure_compare(<<"abc">>, <<"abd">>))
}

// ── JWT ──────────────────────────────────────────────────────────────────────

pub fn jwt_roundtrip_test() {
  let secret = "test-secret-key"
  let token =
    crypto.create_jwt(
      [
        #("sub", json.string("did:plc:abc123")),
        #("scope", json.string("com.atproto.access")),
        #("exp", json.int(now_secs() + 3600)),
      ],
      secret,
    )
  let assert Ok(claims) = crypto.verify_jwt(token, secret)
  should.equal(claims.sub, Some("did:plc:abc123"))
  should.equal(claims.scope, Some("com.atproto.access"))
}

pub fn jwt_wrong_secret_rejected_test() {
  let token =
    crypto.create_jwt(
      [#("sub", json.string("did:x")), #("exp", json.int(now_secs() + 3600))],
      "secret-a",
    )
  crypto.verify_jwt(token, "secret-b")
  |> should.be_error
}

pub fn jwt_expired_rejected_test() {
  let token =
    crypto.create_jwt(
      [#("sub", json.string("did:x")), #("exp", json.int(now_secs() - 10))],
      "secret",
    )
  should.equal(crypto.verify_jwt(token, "secret"), Error(crypto.ExpiredToken))
}

pub fn jwt_tampered_rejected_test() {
  let token =
    crypto.create_jwt(
      [#("sub", json.string("did:x")), #("exp", json.int(now_secs() + 3600))],
      "secret",
    )
  // Flip the payload/signature by appending junk -> must not verify.
  crypto.verify_jwt(token <> "tampered", "secret")
  |> should.be_error
}
