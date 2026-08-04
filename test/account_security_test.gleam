import gleam/dynamic/decode
import gleam/option.{Some}
import gleam_pds/crypto
import gleam_pds/db
import gleeunit/should
import sqlight

pub fn passkeys_schema_supports_multiple_named_test() {
  let assert Ok(conn) = db.connect(":memory:")
  let assert Ok(_) = db.migrate(conn)

  let assert Ok([_]) =
    sqlight.query(
      "SELECT 1 FROM pragma_table_info('passkeys') WHERE name = 'name'",
      conn,
      [],
      decode.at([0], decode.int),
    )

  let assert Ok([_]) =
    sqlight.query(
      "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'idx_passkeys_credential_id'",
      conn,
      [],
      decode.at([0], decode.int),
    )

  let did = "did:plc:testaccount"
  let assert Ok(_) =
    sqlight.query(
      "INSERT INTO accounts (did, handle, password_hash) VALUES (?, ?, ?)",
      conn,
      [
        sqlight.text(did),
        sqlight.text("alice.test"),
        sqlight.text(crypto.hash_password("old-password-1")),
      ],
      decode.at([0], decode.string),
    )

  let assert Ok([_]) =
    sqlight.query(
      "INSERT INTO passkeys (id, did, credential_id, public_key, sign_count, created_at, name)
       VALUES ('pk1', ?, 'cred-a', X'00', 0, datetime('now'), 'Laptop') RETURNING id",
      conn,
      [sqlight.text(did)],
      decode.at([0], decode.string),
    )
  let assert Ok([_]) =
    sqlight.query(
      "INSERT INTO passkeys (id, did, credential_id, public_key, sign_count, created_at, name)
       VALUES ('pk2', ?, 'cred-b', X'01', 0, datetime('now'), ?) RETURNING id",
      conn,
      [sqlight.text(did), sqlight.nullable(sqlight.text, Some("Phone"))],
      decode.at([0], decode.string),
    )

  let assert Ok([count]) =
    sqlight.query(
      "SELECT COUNT(*) FROM passkeys WHERE did = ?",
      conn,
      [sqlight.text(did)],
      decode.at([0], decode.int),
    )
  count |> should.equal(2)

  // Duplicate credential_id must fail under the unique index.
  let dup =
    sqlight.query(
      "INSERT INTO passkeys (id, did, credential_id, public_key, sign_count)
       VALUES ('pk3', ?, 'cred-a', X'02', 0)",
      conn,
      [sqlight.text(did)],
      decode.at([0], decode.string),
    )
  case dup {
    Error(_) -> Nil
    Ok(_) -> should.fail()
  }
}

pub fn password_hash_replace_roundtrip_test() {
  let assert Ok(conn) = db.connect(":memory:")
  let assert Ok(_) = db.migrate(conn)

  let did = "did:plc:pwchange"
  let old_hash = crypto.hash_password("current-secret")
  let assert Ok(_) =
    sqlight.query(
      "INSERT INTO accounts (did, handle, password_hash) VALUES (?, ?, ?)",
      conn,
      [sqlight.text(did), sqlight.text("bob.test"), sqlight.text(old_hash)],
      decode.at([0], decode.string),
    )

  let assert Ok([stored]) =
    sqlight.query(
      "SELECT password_hash FROM accounts WHERE did = ?",
      conn,
      [sqlight.text(did)],
      decode.at([0], decode.string),
    )
  crypto.verify_password("current-secret", stored) |> should.be_true

  let new_hash = crypto.hash_password("brand-new-secret")
  let assert Ok([_]) =
    sqlight.query(
      "UPDATE accounts SET password_hash = ? WHERE did = ? RETURNING did",
      conn,
      [sqlight.text(new_hash), sqlight.text(did)],
      decode.at([0], decode.string),
    )

  let assert Ok([updated]) =
    sqlight.query(
      "SELECT password_hash FROM accounts WHERE did = ?",
      conn,
      [sqlight.text(did)],
      decode.at([0], decode.string),
    )
  crypto.verify_password("brand-new-secret", updated) |> should.be_true
  crypto.verify_password("current-secret", updated) |> should.be_false

  // Session revocation pattern used by update_password: drop other sessions.
  let assert Ok(_) =
    sqlight.query(
      "INSERT INTO sessions (id, did, access_jwt, refresh_jwt, expires_at)
       VALUES ('s1', ?, 'keep-me', 'r1', datetime('now', '+1 hour')),
              ('s2', ?, 'drop-me', 'r2', datetime('now', '+1 hour'))",
      conn,
      [sqlight.text(did), sqlight.text(did)],
      decode.at([0], decode.string),
    )
  let assert Ok(_) =
    sqlight.query(
      "DELETE FROM sessions WHERE did = ? AND access_jwt != ?",
      conn,
      [sqlight.text(did), sqlight.text("keep-me")],
      decode.at([0], decode.string),
    )
  let assert Ok([remaining]) =
    sqlight.query(
      "SELECT access_jwt FROM sessions WHERE did = ?",
      conn,
      [sqlight.text(did)],
      decode.at([0], decode.string),
    )
  remaining |> should.equal("keep-me")
}
