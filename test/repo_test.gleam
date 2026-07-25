//// Integration tests for the repository core (MST + commits) and the db FFI
//// helpers, run against an in-memory SQLite database so the real DAG-CBOR /
//// MST / signing / storage path is exercised end to end.
////
//// These cover the exact regressions found during development:
////  - db access must go through the sqlight-backed gleam_pds@db helpers
////  - a commit must advance the repo head (posts weren't being committed)
////  - the MST must be canonical: the same keys in any order -> the same root
////    (the old incremental MST silently dropped earlier records)

import gleam_pds/crypto
import gleam_pds/db
import gleam/dynamic/decode
import gleam/string
import gleeunit/should
import sqlight

// The repo-core FFI, declared here so tests can drive it directly.
@external(erlang, "gleam_pds_mst_ffi", "init_repo_mst")
fn init_repo_mst(db: sqlight.Connection, did: String) -> String

@external(erlang, "gleam_pds_mst_ffi", "mst_upsert")
fn mst_upsert(
  db: sqlight.Connection,
  did: String,
  key: String,
  value_cid: String,
) -> String

@external(erlang, "gleam_pds_mst_ffi", "sign_and_store_commit")
fn sign_and_store_commit(
  db: sqlight.Connection,
  did: String,
  rev: String,
  root_cid: String,
  private_key: BitArray,
) -> String

// ── fixtures ─────────────────────────────────────────────────────────────────

fn fresh_db() -> sqlight.Connection {
  let assert Ok(conn) = sqlight.open(":memory:")
  let assert Ok(Nil) = db.migrate(conn)
  conn
}

/// Insert a repo row with a fresh signing key; returns the private key.
fn new_repo(conn: sqlight.Connection, did: String) -> BitArray {
  let kp = crypto.generate_p256_keypair()
  let _ =
    sqlight.query(
      "INSERT INTO repos (did, signing_key_private, signing_key_public) VALUES (?, ?, ?)",
      conn,
      [
        sqlight.text(did),
        sqlight.blob(kp.private_key),
        sqlight.blob(kp.public_key),
      ],
      decode.at([0], decode.int),
    )
  kp.private_key
}

/// Write one record (MST upsert + signed commit); returns the new MST root CID.
fn add_record(
  conn: sqlight.Connection,
  did: String,
  priv: BitArray,
  key: String,
  body: BitArray,
) -> String {
  let value_cid = crypto.compute_cid(body)
  let root = mst_upsert(conn, did, key, value_cid)
  let _ = sign_and_store_commit(conn, did, crypto.generate_tid(), root, priv)
  root
}

// ── db FFI helpers ───────────────────────────────────────────────────────────

pub fn block_put_get_roundtrip_test() {
  let conn = fresh_db()
  db.ffi_put_block(conn, "bafyblock", "did:plc:x", <<1, 2, 3>>)
  should.equal(db.ffi_get_block(conn, "bafyblock", "did:plc:x"), Ok(<<1, 2, 3>>))
}

pub fn missing_block_returns_error_test() {
  let conn = fresh_db()
  should.equal(db.ffi_get_block(conn, "nope", "did:plc:x"), Error(Nil))
}

pub fn repo_head_set_get_test() {
  let conn = fresh_db()
  let _ = new_repo(conn, "did:plc:head")
  db.ffi_set_repo_head(conn, "did:plc:head", "commitcid", "3rev")
  should.equal(db.ffi_get_repo_head(conn, "did:plc:head"), Ok("commitcid"))
}

// ── MST / commits ────────────────────────────────────────────────────────────

pub fn empty_mst_root_is_content_addressed_test() {
  let conn = fresh_db()
  // The empty MST root is content-addressed, so it's identical for any repo.
  let a = init_repo_mst(conn, "did:plc:a")
  let b = init_repo_mst(conn, "did:plc:b")
  should.equal(a, b)
  should.be_true(string.starts_with(a, "b"))
}

pub fn commit_advances_head_test() {
  let conn = fresh_db()
  let did = "did:plc:advance"
  let priv = new_repo(conn, did)
  let _ = init_repo_mst(conn, did)

  let root1 = add_record(conn, did, priv, "app.bsky.feed.post/3aaa", <<"one">>)
  let assert Ok(head1) = db.ffi_get_repo_head(conn, did)

  let root2 = add_record(conn, did, priv, "app.bsky.feed.post/3bbb", <<"two">>)
  let assert Ok(head2) = db.ffi_get_repo_head(conn, did)

  // The second write must produce a new tree and a new committed head.
  should.not_equal(root1, root2)
  should.not_equal(head1, head2)
}

pub fn second_write_keeps_first_record_test() {
  // Regression guard: adding a second record must not lose the first. If it
  // did, the two-record root would equal a fresh single-record root.
  let conn = fresh_db()
  let did = "did:plc:keepboth"
  let priv = new_repo(conn, did)
  let _ = init_repo_mst(conn, did)

  let _ = add_record(conn, did, priv, "coll/aaa", <<"first">>)
  let two_record_root =
    add_record(conn, did, priv, "coll/bbb", <<"second">>)

  // A repo containing only the second record has a different root.
  let other = "did:plc:onlysecond"
  let priv2 = new_repo(conn, other)
  let _ = init_repo_mst(conn, other)
  let one_record_root = add_record(conn, other, priv2, "coll/bbb", <<"second">>)

  should.not_equal(two_record_root, one_record_root)
}

pub fn mst_is_order_independent_test() {
  // Canonical MST: the same set of keys inserted in different orders must
  // yield the same root. This is the core "dropped records" regression guard.
  let conn = fresh_db()
  let p1 = new_repo(conn, "did:plc:o1")
  let p2 = new_repo(conn, "did:plc:o2")
  let _ = init_repo_mst(conn, "did:plc:o1")
  let _ = init_repo_mst(conn, "did:plc:o2")

  let _ = add_record(conn, "did:plc:o1", p1, "coll/aaa", <<"a">>)
  let _ = add_record(conn, "did:plc:o1", p1, "coll/bbb", <<"b">>)
  let root_o1 = add_record(conn, "did:plc:o1", p1, "coll/ccc", <<"c">>)

  let _ = add_record(conn, "did:plc:o2", p2, "coll/ccc", <<"c">>)
  let _ = add_record(conn, "did:plc:o2", p2, "coll/aaa", <<"a">>)
  let root_o2 = add_record(conn, "did:plc:o2", p2, "coll/bbb", <<"b">>)

  should.equal(root_o1, root_o2)
}

pub fn migrate_creates_expected_tables_test() {
  // Sanity: migrate/0 runs cleanly and the key tables are queryable.
  let conn = fresh_db()
  let count_decoder = decode.at([0], decode.int)
  should.be_ok(sqlight.query(
    "SELECT COUNT(*) FROM accounts",
    conn,
    [],
    count_decoder,
  ))
  should.be_ok(sqlight.query("SELECT COUNT(*) FROM repos", conn, [], count_decoder))
  should.be_ok(sqlight.query(
    "SELECT COUNT(*) FROM blocks",
    conn,
    [],
    count_decoder,
  ))
  should.be_ok(sqlight.query(
    "SELECT COUNT(*) FROM firehose_events",
    conn,
    [],
    count_decoder,
  ))
}
