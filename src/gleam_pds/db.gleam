import gleam/dynamic/decode
import gleam/int
import gleam/io
import sqlight

/// Current schema version recorded in `schema_migrations` after migrate/0 runs.
/// Bump this whenever a new migration step is added below.
pub const schema_version: Int = 4

/// Maximum allowed size (in bytes) for an inline blob stored in SQLite.
/// Blob bytes are stored directly in `blobs.data` with no DB-level limit, so
/// unbounded uploads can bloat the single SQLite file catastrophically.
/// NOTE: db.gleam has no blob insert helper — the actual insert happens in
/// repo.gleam's upload_blob handler (owned by another agent). That handler
/// SHOULD enforce this constant and reject uploads larger than it (413/400)
/// BEFORE reading the full body into memory / inserting. 5 MiB matches the
/// common AT Protocol default blob limit.
pub const max_blob_size: Int = 5_242_880

/// Open a connection to the SQLite database at the given path.
pub fn connect(db_path: String) -> Result(sqlight.Connection, sqlight.Error) {
  sqlight.open(db_path)
}

/// Run all database migrations. Creates tables if they don't exist.
pub fn migrate(db: sqlight.Connection) -> Result(Nil, sqlight.Error) {
  // Enable WAL mode for better concurrent performance
  let assert Ok(_) = sqlight.exec("PRAGMA journal_mode=WAL;", db)
  let assert Ok(_) = sqlight.exec("PRAGMA foreign_keys=ON;", db)

  io.println("[db] Running migrations...")

  let assert Ok(_) = create_accounts_table(db)
  let assert Ok(_) = create_sessions_table(db)
  let assert Ok(_) = create_repos_table(db)
  let assert Ok(_) = create_records_table(db)
  let assert Ok(_) = create_blobs_table(db)
  let assert Ok(_) = create_passkeys_table(db)
  let assert Ok(_) = create_oauth_codes_table(db)
  let assert Ok(_) = create_oauth_tokens_table(db)
  let assert Ok(_) = create_webauthn_challenges_table(db)
  let assert Ok(_) = create_oauth_auth_requests_table(db)
  let assert Ok(_) = migrate_repos_add_key_columns(db)
  let assert Ok(_) = create_actor_preferences_table(db)
  let assert Ok(_) = migrate_oauth_tokens_add_refresh_expires(db)
  let assert Ok(_) = migrate_records_add_cbor(db)
  let assert Ok(_) = create_blocks_table(db)

  // --- Hardening migrations (schema_version 1) ---
  let assert Ok(_) = create_schema_migrations_table(db)
  let assert Ok(_) = create_firehose_events_table(db)
  let assert Ok(_) = migrate_accounts_add_status_columns(db)
  let assert Ok(_) = create_app_passwords_table(db)
  let assert Ok(_) = create_blob_refs_table(db)

  // --- schema_version 2 ---
  let assert Ok(_) = migrate_sessions_add_scope(db)

  // --- schema_version 3 ---
  let assert Ok(_) = migrate_oauth_auth_requests_add_login_hint(db)

  // --- schema_version 4: ATProto permissioned-data / spaces scaffold ---
  let assert Ok(_) = create_space_tables(db)

  let assert Ok(_) = create_indexes(db)
  let assert Ok(_) = record_schema_version(db)

  io.println("[db] Migrations complete.")
  Ok(Nil)
}

/// Lightweight migration-versioning table. We keep the ad-hoc additive
/// migrations above (they are all idempotent) but now also record a version
/// so the applied schema level is observable. Backward compatible: existing
/// databases simply get this table + a version row on next boot.
fn create_schema_migrations_table(
  db: sqlight.Connection,
) -> Result(Nil, sqlight.Error) {
  sqlight.exec(
    "
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      applied_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    ",
    db,
  )
}

/// Record the current schema version. INSERT OR IGNORE keeps it idempotent so
/// re-running migrate/0 does not fail or duplicate rows. Also mirror it into
/// the SQLite `user_version` pragma for cheap out-of-band inspection.
fn record_schema_version(
  db: sqlight.Connection,
) -> Result(Nil, sqlight.Error) {
  let version = int.to_string(schema_version)
  let _ =
    sqlight.exec(
      "INSERT OR IGNORE INTO schema_migrations (version) VALUES ("
        <> version
        <> ");",
      db,
    )
  let _ = sqlight.exec("PRAGMA user_version = " <> version <> ";", db)
  Ok(Nil)
}

/// Durable firehose sequencer / event log. `seq` is the monotonically
/// increasing cursor consumers subscribe from; `frame` holds the fully-encoded
/// frame bytes so events survive restarts (in-memory firehose alone is lossy).
fn create_firehose_events_table(
  db: sqlight.Connection,
) -> Result(Nil, sqlight.Error) {
  sqlight.exec(
    "
    CREATE TABLE IF NOT EXISTS firehose_events (
      seq INTEGER PRIMARY KEY AUTOINCREMENT,
      did TEXT,
      type TEXT NOT NULL,
      frame BLOB NOT NULL,
      time TEXT NOT NULL
    );
    ",
    db,
  )
}

/// Account lifecycle / moderation columns. Idempotent: an already-exists error
/// on ADD COLUMN is swallowed (SQLite has no IF NOT EXISTS for ALTER).
fn migrate_accounts_add_status_columns(
  db: sqlight.Connection,
) -> Result(Nil, sqlight.Error) {
  let _ =
    sqlight.exec("ALTER TABLE accounts ADD COLUMN deactivated_at TEXT;", db)
  let _ =
    sqlight.exec(
      "ALTER TABLE accounts ADD COLUMN email_verified INTEGER DEFAULT 0;",
      db,
    )
  let _ = sqlight.exec("ALTER TABLE accounts ADD COLUMN takedown_ref TEXT;", db)
  Ok(Nil)
}

/// Access scope of a session ("com.atproto.access" for a main-password login,
/// "com.atproto.appPass" for an app-password login). NULL on rows created
/// before this column existed; those are treated as full access.
fn migrate_sessions_add_scope(
  db: sqlight.Connection,
) -> Result(Nil, sqlight.Error) {
  let _ = sqlight.exec("ALTER TABLE sessions ADD COLUMN scope TEXT;", db)
  Ok(Nil)
}

/// OAuth clients may send `login_hint` (the handle the user typed on the
/// client site) with the pushed authorization request; the authorize form
/// prefills it. NULL on rows from before this column existed.
fn migrate_oauth_auth_requests_add_login_hint(
  db: sqlight.Connection,
) -> Result(Nil, sqlight.Error) {
  let _ =
    sqlight.exec("ALTER TABLE oauth_auth_requests ADD COLUMN login_hint TEXT;", db)
  Ok(Nil)
}

/// Space tables for ATProto permissioned-data (schema_version 4).
/// Mirrors bluesky-social/atproto `permissioned-data` branch migration
/// `packages/pds/src/actor-store/db/migrations/002-space.ts`, adapted to
/// gleam-pds SQLite TEXT/INTEGER/BLOB style. Handlers are stubs; these tables
/// exist so later work can persist spaces without another schema bump.
fn create_space_tables(db: sqlight.Connection) -> Result(Nil, sqlight.Error) {
  let assert Ok(_) =
    sqlight.exec(
      "
      CREATE TABLE IF NOT EXISTS space (
        uri TEXT PRIMARY KEY,
        is_owner INTEGER NOT NULL,
        policy TEXT NOT NULL DEFAULT 'member-list',
        managing_app TEXT,
        app_access_type TEXT NOT NULL DEFAULT 'open',
        app_allowed TEXT NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL,
        deleted_at TEXT
      );
      ",
      db,
    )
  let assert Ok(_) =
    sqlight.exec(
      "
      CREATE TABLE IF NOT EXISTS space_member (
        space TEXT NOT NULL,
        did TEXT NOT NULL,
        PRIMARY KEY (space, did)
      );
      ",
      db,
    )
  let assert Ok(_) =
    sqlight.exec(
      "
      CREATE TABLE IF NOT EXISTS space_record (
        space TEXT NOT NULL,
        collection TEXT NOT NULL,
        rkey TEXT NOT NULL,
        cid TEXT NOT NULL,
        value BLOB NOT NULL,
        repo_rev TEXT NOT NULL,
        indexed_at TEXT NOT NULL,
        PRIMARY KEY (space, collection, rkey)
      );
      ",
      db,
    )
  let assert Ok(_) =
    sqlight.exec(
      "CREATE INDEX IF NOT EXISTS space_record_rev_idx ON space_record(space, repo_rev);",
      db,
    )
  let assert Ok(_) =
    sqlight.exec(
      "
      CREATE TABLE IF NOT EXISTS space_repo (
        space TEXT PRIMARY KEY,
        set_hash BLOB,
        rev TEXT
      );
      ",
      db,
    )
  let assert Ok(_) =
    sqlight.exec(
      "
      CREATE TABLE IF NOT EXISTS space_record_oplog (
        space TEXT NOT NULL,
        rev TEXT NOT NULL,
        idx INTEGER NOT NULL,
        action TEXT NOT NULL,
        collection TEXT NOT NULL,
        rkey TEXT NOT NULL,
        cid TEXT,
        prev TEXT,
        PRIMARY KEY (space, rev, idx)
      );
      ",
      db,
    )
  let assert Ok(_) =
    sqlight.exec(
      "
      CREATE TABLE IF NOT EXISTS space_writer (
        space TEXT NOT NULL,
        did TEXT NOT NULL,
        rev TEXT NOT NULL,
        hash BLOB NOT NULL,
        PRIMARY KEY (space, did)
      );
      ",
      db,
    )
  let assert Ok(_) =
    sqlight.exec(
      "
      CREATE TABLE IF NOT EXISTS space_credential_recipient (
        space TEXT NOT NULL,
        service_did TEXT NOT NULL,
        service_endpoint TEXT NOT NULL,
        last_issued_at TEXT NOT NULL,
        PRIMARY KEY (space, service_did)
      );
      ",
      db,
    )
  Ok(Nil)
}

/// App-specific passwords (scoped credentials distinct from the main password).
fn create_app_passwords_table(
  db: sqlight.Connection,
) -> Result(Nil, sqlight.Error) {
  sqlight.exec(
    "
    CREATE TABLE IF NOT EXISTS app_passwords (
      did TEXT,
      name TEXT,
      password_hash TEXT,
      created_at TEXT
    );
    ",
    db,
  )
}

/// Reference counts for blobs, so unreferenced blobs can be garbage-collected.
/// Created regardless of whether it is populated yet.
fn create_blob_refs_table(
  db: sqlight.Connection,
) -> Result(Nil, sqlight.Error) {
  sqlight.exec(
    "
    CREATE TABLE IF NOT EXISTS blob_refs (
      cid TEXT,
      did TEXT,
      record_uri TEXT
    );
    ",
    db,
  )
}

/// Indexes that were entirely missing — every lookup by `did` (and the record
/// composite keys) was doing a full table scan. All idempotent via IF NOT
/// EXISTS. Indexes on oauth_tokens/oauth_codes match their existing columns:
/// oauth_tokens has `refresh_token` + `did`; oauth_codes is keyed on `code`
/// (already a PK) but is frequently looked up by `did`.
fn create_indexes(db: sqlight.Connection) -> Result(Nil, sqlight.Error) {
  let _ =
    sqlight.exec("CREATE INDEX IF NOT EXISTS idx_records_did ON records(did);", db)
  let _ =
    sqlight.exec(
      "CREATE INDEX IF NOT EXISTS idx_records_did_collection ON records(did, collection);",
      db,
    )
  let _ =
    sqlight.exec(
      "CREATE INDEX IF NOT EXISTS idx_records_did_collection_rkey ON records(did, collection, rkey);",
      db,
    )
  let _ =
    sqlight.exec("CREATE INDEX IF NOT EXISTS idx_blobs_did ON blobs(did);", db)
  let _ =
    sqlight.exec("CREATE INDEX IF NOT EXISTS idx_blocks_did ON blocks(did);", db)
  let _ =
    sqlight.exec(
      "CREATE INDEX IF NOT EXISTS idx_sessions_did ON sessions(did);",
      db,
    )
  let _ =
    sqlight.exec(
      "CREATE INDEX IF NOT EXISTS idx_firehose_events_did ON firehose_events(did);",
      db,
    )
  let _ =
    sqlight.exec(
      "CREATE INDEX IF NOT EXISTS idx_app_passwords_did ON app_passwords(did);",
      db,
    )
  let _ =
    sqlight.exec(
      "CREATE INDEX IF NOT EXISTS idx_blob_refs_cid ON blob_refs(cid);",
      db,
    )
  // oauth lookups: refresh_token is used to rotate tokens; did to enumerate.
  let _ =
    sqlight.exec(
      "CREATE INDEX IF NOT EXISTS idx_oauth_tokens_refresh_token ON oauth_tokens(refresh_token);",
      db,
    )
  let _ =
    sqlight.exec(
      "CREATE INDEX IF NOT EXISTS idx_oauth_tokens_did ON oauth_tokens(did);",
      db,
    )
  let _ =
    sqlight.exec(
      "CREATE INDEX IF NOT EXISTS idx_oauth_codes_did ON oauth_codes(did);",
      db,
    )
  Ok(Nil)
}

fn create_accounts_table(
  db: sqlight.Connection,
) -> Result(Nil, sqlight.Error) {
  sqlight.exec(
    "
    CREATE TABLE IF NOT EXISTS accounts (
      did TEXT PRIMARY KEY,
      handle TEXT UNIQUE,
      email TEXT,
      password_hash TEXT,
      created_at TEXT
    );
    ",
    db,
  )
}

fn create_sessions_table(
  db: sqlight.Connection,
) -> Result(Nil, sqlight.Error) {
  sqlight.exec(
    "
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      did TEXT,
      access_jwt TEXT,
      refresh_jwt TEXT,
      created_at TEXT,
      expires_at TEXT
    );
    ",
    db,
  )
}

fn create_repos_table(db: sqlight.Connection) -> Result(Nil, sqlight.Error) {
  sqlight.exec(
    "
    CREATE TABLE IF NOT EXISTS repos (
      did TEXT PRIMARY KEY,
      head TEXT,
      rev TEXT,
      signing_key TEXT,
      signing_key_private BLOB,
      signing_key_public BLOB
    );
    ",
    db,
  )
}

fn create_records_table(db: sqlight.Connection) -> Result(Nil, sqlight.Error) {
  sqlight.exec(
    "
    CREATE TABLE IF NOT EXISTS records (
      uri TEXT PRIMARY KEY,
      did TEXT,
      collection TEXT,
      rkey TEXT,
      record TEXT,
      cid TEXT,
      created_at TEXT
    );
    ",
    db,
  )
}

fn create_blobs_table(db: sqlight.Connection) -> Result(Nil, sqlight.Error) {
  sqlight.exec(
    "
    CREATE TABLE IF NOT EXISTS blobs (
      cid TEXT PRIMARY KEY,
      did TEXT,
      mime_type TEXT,
      size INTEGER,
      data BLOB,
      created_at TEXT
    );
    ",
    db,
  )
}

fn create_passkeys_table(
  db: sqlight.Connection,
) -> Result(Nil, sqlight.Error) {
  sqlight.exec(
    "
    CREATE TABLE IF NOT EXISTS passkeys (
      id TEXT PRIMARY KEY,
      did TEXT,
      credential_id TEXT,
      public_key BLOB,
      sign_count INTEGER,
      created_at TEXT
    );
    ",
    db,
  )
}

fn create_oauth_codes_table(
  db: sqlight.Connection,
) -> Result(Nil, sqlight.Error) {
  sqlight.exec(
    "
    CREATE TABLE IF NOT EXISTS oauth_codes (
      code TEXT PRIMARY KEY,
      did TEXT,
      client_id TEXT,
      redirect_uri TEXT,
      code_challenge TEXT,
      code_challenge_method TEXT,
      scope TEXT,
      created_at TEXT,
      expires_at TEXT
    );
    ",
    db,
  )
}

fn create_oauth_tokens_table(
  db: sqlight.Connection,
) -> Result(Nil, sqlight.Error) {
  sqlight.exec(
    "
    CREATE TABLE IF NOT EXISTS oauth_tokens (
      access_token TEXT PRIMARY KEY,
      did TEXT,
      client_id TEXT,
      scope TEXT,
      created_at TEXT,
      expires_at TEXT,
      refresh_token TEXT
    );
    ",
    db,
  )
}

fn create_webauthn_challenges_table(
  db: sqlight.Connection,
) -> Result(Nil, sqlight.Error) {
  sqlight.exec(
    "
    CREATE TABLE IF NOT EXISTS webauthn_challenges (
      challenge TEXT PRIMARY KEY,
      did TEXT,
      type TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      expires_at TEXT NOT NULL
    );
    ",
    db,
  )
}

fn create_oauth_auth_requests_table(
  db: sqlight.Connection,
) -> Result(Nil, sqlight.Error) {
  sqlight.exec(
    "
    CREATE TABLE IF NOT EXISTS oauth_auth_requests (
      id TEXT PRIMARY KEY,
      client_id TEXT NOT NULL,
      redirect_uri TEXT NOT NULL,
      code_challenge TEXT NOT NULL,
      code_challenge_method TEXT NOT NULL DEFAULT 'S256',
      scope TEXT NOT NULL DEFAULT '',
      state TEXT,
      did TEXT,
      code TEXT UNIQUE,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      expires_at TEXT NOT NULL
    );
    ",
    db,
  )
}

fn migrate_repos_add_key_columns(
  db: sqlight.Connection,
) -> Result(Nil, sqlight.Error) {
  // Add columns if they don't exist (SQLite doesn't have IF NOT EXISTS for ALTER)
  let _ = sqlight.exec(
    "ALTER TABLE repos ADD COLUMN signing_key_private BLOB;",
    db,
  )
  let _ = sqlight.exec(
    "ALTER TABLE repos ADD COLUMN signing_key_public BLOB;",
    db,
  )
  Ok(Nil)
}

fn create_actor_preferences_table(
  db: sqlight.Connection,
) -> Result(Nil, sqlight.Error) {
  sqlight.exec(
    "
    CREATE TABLE IF NOT EXISTS actor_preferences (
      did TEXT PRIMARY KEY,
      preferences TEXT NOT NULL DEFAULT '{}'
    );
    ",
    db,
  )
}

fn migrate_oauth_tokens_add_refresh_expires(
  db: sqlight.Connection,
) -> Result(Nil, sqlight.Error) {
  let _ = sqlight.exec(
    "ALTER TABLE oauth_tokens ADD COLUMN refresh_expires_at TEXT;",
    db,
  )
  Ok(Nil)
}

fn migrate_records_add_cbor(
  db: sqlight.Connection,
) -> Result(Nil, sqlight.Error) {
  let _ = sqlight.exec(
    "ALTER TABLE records ADD COLUMN record_cbor BLOB;",
    db,
  )
  Ok(Nil)
}

fn create_blocks_table(db: sqlight.Connection) -> Result(Nil, sqlight.Error) {
  sqlight.exec(
    "
    CREATE TABLE IF NOT EXISTS blocks (
      cid TEXT PRIMARY KEY,
      did TEXT,
      data BLOB,
      created_at TEXT DEFAULT (datetime('now'))
    );
    ",
    db,
  )
}

// ── FFI database helpers ─────────────────────────────────────────────────────
// The Erlang FFI modules (gleam_pds_mst_ffi, gleam_pds_firehose_ffi) need to read and
// write blocks / repo rows, but they cannot call esqlite3 directly: sqlight's
// connection is an opaque {esqlite3, Ref} wrapper that esqlite3:q/prepare
// rejects. These Gleam wrappers run the queries through sqlight (which owns the
// connection) and are invoked from Erlang as `gleam_pds@db:ffi_*`.

/// Read a repo block by CID. Returns Error(Nil) when absent.
pub fn ffi_get_block(
  conn: sqlight.Connection,
  cid: String,
  did: String,
) -> Result(BitArray, Nil) {
  case
    sqlight.query(
      "SELECT data FROM blocks WHERE cid = ? AND did = ? LIMIT 1",
      conn,
      [sqlight.text(cid), sqlight.text(did)],
      decode.at([0], decode.bit_array),
    )
  {
    Ok([data, ..]) -> Ok(data)
    _ -> Error(Nil)
  }
}

/// Insert or replace a repo block.
pub fn ffi_put_block(
  conn: sqlight.Connection,
  cid: String,
  did: String,
  data: BitArray,
) -> Nil {
  let _ =
    sqlight.query(
      "INSERT OR REPLACE INTO blocks (cid, did, data) VALUES (?, ?, ?)",
      conn,
      [sqlight.text(cid), sqlight.text(did), sqlight.blob(data)],
      decode.at([0], decode.int),
    )
  Nil
}

/// Read a repo's current head (latest commit CID). Error(Nil) when unset/NULL.
pub fn ffi_get_repo_head(
  conn: sqlight.Connection,
  did: String,
) -> Result(String, Nil) {
  case
    sqlight.query(
      "SELECT head FROM repos WHERE did = ? LIMIT 1",
      conn,
      [sqlight.text(did)],
      decode.at([0], decode.string),
    )
  {
    Ok([head, ..]) -> Ok(head)
    _ -> Error(Nil)
  }
}

/// Update a repo's head commit CID and rev.
pub fn ffi_set_repo_head(
  conn: sqlight.Connection,
  did: String,
  head: String,
  rev: String,
) -> Nil {
  let _ =
    sqlight.query(
      "UPDATE repos SET head = ?, rev = ? WHERE did = ?",
      conn,
      [sqlight.text(head), sqlight.text(rev), sqlight.text(did)],
      decode.at([0], decode.int),
    )
  Nil
}

/// Read a record block's CBOR by CID. Error(Nil) when absent.
pub fn ffi_get_record_cbor(
  conn: sqlight.Connection,
  cid: String,
  did: String,
) -> Result(BitArray, Nil) {
  case
    sqlight.query(
      "SELECT record_cbor FROM records WHERE cid = ? AND did = ? LIMIT 1",
      conn,
      [sqlight.text(cid), sqlight.text(did)],
      decode.at([0], decode.bit_array),
    )
  {
    Ok([data, ..]) -> Ok(data)
    _ -> Error(Nil)
  }
}
