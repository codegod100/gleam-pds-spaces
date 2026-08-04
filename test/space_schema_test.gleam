import gleam/dynamic/decode
import gleam_pds/db
import gleeunit/should
import sqlight

pub fn space_tables_migrate_test() {
  let assert Ok(conn) = db.connect(":memory:")
  let assert Ok(_) = db.migrate(conn)

  let assert Ok(tables) =
    sqlight.query(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'space%' ORDER BY 1",
      conn,
      [],
      decode.at([0], decode.string),
    )

  tables
  |> should.equal([
    "space",
    "space_credential_recipient",
    "space_member",
    "space_record",
    "space_record_oplog",
    "space_repo",
    "space_writer",
  ])

  let assert Ok([version]) =
    sqlight.query(
      "SELECT MAX(version) FROM schema_migrations",
      conn,
      [],
      decode.at([0], decode.int),
    )
  version |> should.equal(db.schema_version)
  version |> should.equal(5)

  let assert Ok([_]) =
    sqlight.query(
      "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'space_record_rev_idx'",
      conn,
      [],
      decode.at([0], decode.int),
    )
}
