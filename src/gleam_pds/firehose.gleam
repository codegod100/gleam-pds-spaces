/// AT Protocol Firehose (com.atproto.sync.subscribeRepos)
///
/// Manages WebSocket subscribers, persists every emitted event into the
/// `firehose_events` table (which assigns the authoritative `seq` cursor),
/// broadcasts to live subscribers, and replays backlog on reconnect.

import gleam_pds/config.{type Config}
import birl
import gleam/dynamic/decode
import gleam/erlang/process.{type Subject}
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/httpc
import gleam/int
import gleam/io
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/otp/actor
import mist
import sqlight

// --- Types ---

pub type FirehoseEvent {
  CommitEvent(
    did: String,
    collection: String,
    rkey: String,
    action: String,
    record_cbor: BitArray,
    cid: String,
    rev: String,
    commit_cid: String,
    // previous commit rev ("" if genesis) -> #commit.since
    since: String,
    // previous record CID ("" if none) -> op.prev
    prev_record_cid: String,
    // previous commit CID ("" if genesis) -> used to derive prevData
    prev_commit_cid: String,
  )
  AccountEvent(did: String, active: Bool)
  IdentityEvent(did: String, handle: String)
  SyncEvent(did: String, rev: String, commit_cid: String)
}

pub type Message {
  Subscribe(subject: Subject(BitArray))
  Unsubscribe(subject: Subject(BitArray))
  Emit(event: FirehoseEvent)
  RequestCrawl(config: Config)
}

pub type State {
  State(
    subscribers: List(Subject(BitArray)),
    db: sqlight.Connection,
    // unix seconds of the last relay crawl request (throttling)
    last_crawl: Int,
  )
}

// --- CBOR / FFI ---

@external(erlang, "gleam_pds_cbor_ffi", "encode_header_and_body")
fn cbor_encode_header_and_body(header: anything, body: anything) -> BitArray

@external(erlang, "gleam_pds_cbor_ffi", "build_car_file")
pub fn build_car_file(
  root_cid_bytes: BitArray,
  blocks: List(#(BitArray, BitArray)),
) -> BitArray

@external(erlang, "gleam_pds_cbor_ffi", "cid_bytes_from_base32")
pub fn cid_bytes_from_base32(cid_string: String) -> BitArray

// Gather the complete, importable block set reachable from a commit CID:
// commit block + MST nodes + record leaf blocks (deduplicated, no orphans).
@external(erlang, "gleam_pds_firehose_ffi", "collect_repo_blocks")
fn collect_repo_blocks(
  db: sqlight.Connection,
  did: String,
  commit_cid: String,
) -> List(#(BitArray, BitArray))

// Return the MST root (data) CID string of a commit, "" if unavailable.
@external(erlang, "gleam_pds_firehose_ffi", "commit_data_cid")
fn commit_data_cid(
  db: sqlight.Connection,
  did: String,
  commit_cid: String,
) -> String

@external(erlang, "gleam_pds_firehose_ffi", "make_commit_header")
fn make_commit_header() -> anything

@external(erlang, "gleam_pds_firehose_ffi", "make_commit_body")
fn make_commit_body(
  seq: Int,
  did: String,
  time: String,
  rev: String,
  since: String,
  commit_cid_bytes: BitArray,
  prev_data_cid_bytes: BitArray,
  blocks: BitArray,
  ops_action: String,
  ops_path: String,
  ops_cid_bytes: BitArray,
  ops_prev_cid_bytes: BitArray,
) -> anything

@external(erlang, "gleam_pds_firehose_ffi", "make_account_header")
fn make_account_header() -> anything

@external(erlang, "gleam_pds_firehose_ffi", "make_account_body")
fn make_account_body(
  seq: Int,
  did: String,
  time: String,
  active: Bool,
) -> anything

@external(erlang, "gleam_pds_firehose_ffi", "make_identity_header")
fn make_identity_header() -> anything

@external(erlang, "gleam_pds_firehose_ffi", "make_identity_body")
fn make_identity_body(
  seq: Int,
  did: String,
  time: String,
  handle: String,
) -> anything

@external(erlang, "gleam_pds_firehose_ffi", "make_sync_header")
fn make_sync_header() -> anything

@external(erlang, "gleam_pds_firehose_ffi", "make_sync_body")
fn make_sync_body(
  seq: Int,
  did: String,
  time: String,
  rev: String,
  blocks: BitArray,
) -> anything

@external(erlang, "gleam_pds_firehose_ffi", "make_info_header")
fn make_info_header() -> anything

@external(erlang, "gleam_pds_firehose_ffi", "make_info_body")
fn make_info_body(name: String, message: String) -> anything

// --- Actor ---

pub fn start(
  db: sqlight.Connection,
) -> Result(Subject(Message), actor.StartError) {
  let result =
    actor.new(State(subscribers: [], db: db, last_crawl: 0))
    |> actor.on_message(handle_message)
    |> actor.start
  case result {
    Ok(started) -> Ok(started.data)
    Error(err) -> Error(err)
  }
}

fn handle_message(
  state: State,
  message: Message,
) -> actor.Next(State, Message) {
  case message {
    Subscribe(subject) ->
      actor.continue(
        State(..state, subscribers: [subject, ..state.subscribers]),
      )

    Unsubscribe(subject) -> {
      let new_subs = list.filter(state.subscribers, fn(s) { s != subject })
      actor.continue(State(..state, subscribers: new_subs))
    }

    Emit(event) -> {
      // Persist first so the DB assigns the authoritative seq, then encode the
      // frame (which embeds seq), store the frame bytes, and broadcast.
      let #(type_str, did) = event_type_did(event)
      let seq = insert_event(state.db, did, type_str)
      let frame = encode_frame(state.db, seq, event)
      let _ = store_frame(state.db, seq, frame)
      list.each(state.subscribers, fn(sub) { process.send(sub, frame) })
      actor.continue(state)
    }

    RequestCrawl(cfg) -> {
      let now = birl.to_unix(birl.utc_now())
      // Throttle to at most once per 20 minutes.
      case now - state.last_crawl >= 1200 {
        True -> {
          do_request_crawl(cfg)
          actor.continue(State(..state, last_crawl: now))
        }
        False -> actor.continue(state)
      }
    }
  }
}

fn event_type_did(event: FirehoseEvent) -> #(String, String) {
  case event {
    CommitEvent(did: did, ..) -> #("#commit", did)
    AccountEvent(did, _) -> #("#account", did)
    IdentityEvent(did, _) -> #("#identity", did)
    SyncEvent(did, _, _) -> #("#sync", did)
  }
}

fn now_iso() -> String {
  birl.to_iso8601(birl.utc_now())
}

// --- Event persistence (sequencer) ---

/// Insert a placeholder row so the DB assigns the monotonic seq, returning it.
fn insert_event(db: sqlight.Connection, did: String, type_str: String) -> Int {
  let time = now_iso()
  case
    sqlight.query(
      "INSERT INTO firehose_events (did, type, frame, time) VALUES (?, ?, ?, ?) RETURNING seq",
      db,
      [
        sqlight.text(did),
        sqlight.text(type_str),
        sqlight.blob(<<>>),
        sqlight.text(time),
      ],
      decode.at([0], decode.int),
    )
  {
    Ok([s]) -> s
    _ -> 0
  }
}

/// Store the fully-encoded frame bytes against the assigned seq.
fn store_frame(db: sqlight.Connection, seq: Int, frame: BitArray) -> Nil {
  let _ =
    sqlight.query(
      "UPDATE firehose_events SET frame = ? WHERE seq = ?",
      db,
      [sqlight.blob(frame), sqlight.int(seq)],
      decode.at([0], decode.int),
    )
  Nil
}

// --- Frame encoding ---

fn encode_frame(
  db: sqlight.Connection,
  seq: Int,
  event: FirehoseEvent,
) -> BitArray {
  case event {
    CommitEvent(
      did,
      collection,
      rkey,
      action,
      _record_cbor,
      cid,
      rev,
      commit_cid,
      since,
      prev_record_cid,
      prev_commit_cid,
    ) -> {
      let time = now_iso()
      let commit_cid_bytes = cid_bytes_from_base32(commit_cid)
      // "" for deletes -> <<>> -> op.cid becomes null (no garbage block).
      let record_cid_bytes = cid_bytes_from_base32(cid)
      let path = collection <> "/" <> rkey

      // Covering proof: commit block + reachable MST nodes + record leaf blocks.
      let blocks = collect_repo_blocks(db, did, commit_cid)
      let car_bytes = build_car_file(commit_cid_bytes, blocks)

      // prevData = MST root CID of the previous commit (for inductive firehose).
      let prev_data_bytes =
        cid_bytes_from_base32(commit_data_cid(db, did, prev_commit_cid))
      let prev_record_bytes = cid_bytes_from_base32(prev_record_cid)

      let header = make_commit_header()
      let body =
        make_commit_body(
          seq,
          did,
          time,
          rev,
          since,
          commit_cid_bytes,
          prev_data_bytes,
          car_bytes,
          action,
          path,
          record_cid_bytes,
          prev_record_bytes,
        )
      cbor_encode_header_and_body(header, body)
    }

    AccountEvent(did, active) ->
      cbor_encode_header_and_body(
        make_account_header(),
        make_account_body(seq, did, now_iso(), active),
      )

    IdentityEvent(did, handle) ->
      cbor_encode_header_and_body(
        make_identity_header(),
        make_identity_body(seq, did, now_iso(), handle),
      )

    SyncEvent(did, rev, commit_cid) -> {
      let blocks = collect_repo_blocks(db, did, commit_cid)
      let car = build_car_file(cid_bytes_from_base32(commit_cid), blocks)
      cbor_encode_header_and_body(
        make_sync_header(),
        make_sync_body(seq, did, now_iso(), rev, car),
      )
    }
  }
}

/// Convenience: emit #account (active) + #identity events for a new account so
/// relays begin indexing it. Call this right after a repo is initialized.
pub fn emit_account_created(
  firehose: Subject(Message),
  did: String,
  handle: String,
) -> Nil {
  process.send(firehose, Emit(AccountEvent(did, True)))
  process.send(firehose, Emit(IdentityEvent(did, handle)))
}

// --- Backlog replay helpers ---

fn parse_cursor(req: request.Request(mist.Connection)) -> Option(Int) {
  case request.get_query(req) {
    Ok(params) ->
      case list.key_find(params, "cursor") {
        Ok(v) ->
          case int.parse(v) {
            Ok(n) -> Some(n)
            Error(_) -> None
          }
        Error(_) -> None
      }
    Error(_) -> None
  }
}

/// Smallest stored seq, if any events exist.
fn oldest_seq(db: sqlight.Connection) -> Option(Int) {
  case
    sqlight.query(
      "SELECT MIN(seq) FROM firehose_events",
      db,
      [],
      decode.at([0], decode.optional(decode.int)),
    )
  {
    Ok([Some(n)]) -> Some(n)
    _ -> None
  }
}

/// Load all stored frames with seq > cursor, in order.
fn load_backlog(db: sqlight.Connection, cursor: Int) -> List(BitArray) {
  case
    sqlight.query(
      "SELECT frame FROM firehose_events WHERE seq > ? ORDER BY seq ASC",
      db,
      [sqlight.int(cursor)],
      decode.at([0], decode.bit_array),
    )
  {
    Ok(frames) -> frames
    Error(_) -> []
  }
}

fn outdated_cursor_frame() -> BitArray {
  cbor_encode_header_and_body(
    make_info_header(),
    make_info_body(
      "OutdatedCursor",
      "requested cursor is before the oldest available event",
    ),
  )
}

// --- WebSocket Handler ---

/// Handle a WebSocket upgrade request for subscribeRepos.
pub fn handle_websocket(
  req: request.Request(mist.Connection),
  firehose: Subject(Message),
  db: sqlight.Connection,
) -> response.Response(mist.ResponseData) {
  mist.websocket(
    request: req,
    handler: fn(state, msg, conn) {
      case msg {
        mist.Binary(_data) -> mist.continue(state)
        mist.Text(_text) -> mist.continue(state)
        mist.Custom(frame_data) -> {
          let _ = mist.send_binary_frame(conn, frame_data)
          mist.continue(state)
        }
        mist.Closed | mist.Shutdown -> mist.stop()
      }
    },
    on_init: fn(_conn) {
      // Subject on which this connection receives firehose frames.
      let subj = process.new_subject()

      // Backlog replay: enqueue stored frames BEFORE subscribing to live
      // events so ordering is preserved (backlog frames land in the mailbox
      // ahead of any live frame).
      case parse_cursor(req) {
        Some(cursor) -> {
          case oldest_seq(db) {
            Some(min_seq) if cursor + 1 < min_seq ->
              process.send(subj, outdated_cursor_frame())
            _ -> Nil
          }
          list.each(load_backlog(db, cursor), fn(frame) {
            process.send(subj, frame)
          })
        }
        None -> Nil
      }

      // Register as a live subscriber.
      process.send(firehose, Subscribe(subj))

      let selector =
        process.new_selector()
        |> process.select(subj)

      #(subj, Some(selector))
    },
    on_close: fn(subj) {
      // Remove the subscriber so we don't leak dead subjects (H4).
      process.send(firehose, Unsubscribe(subj))
      Nil
    },
  )
}

// --- Request Crawl ---

/// Notify the Bluesky relay to crawl this PDS. Prefer sending a
/// `RequestCrawl` message to the actor (which throttles); this performs the
/// actual HTTP request in a background process.
fn do_request_crawl(config: Config) -> Nil {
  let _ =
    process.spawn(fn() {
      let body = "{\"hostname\":\"" <> config.hostname <> "\"}"
      let req =
        request.new()
        |> request.set_method(http.Post)
        |> request.set_host("bsky.network")
        |> request.set_path("/xrpc/com.atproto.sync.requestCrawl")
        |> request.set_scheme(http.Https)
        |> request.set_body(body)
        |> request.set_header("content-type", "application/json")
      case httpc.send(req) {
        Ok(resp) -> {
          io.println(
            "[firehose] Crawl request sent, status: "
            <> case resp.status {
              200 -> "200 OK"
              _ -> "non-200"
            },
          )
          Nil
        }
        Error(_) -> {
          io.println("[firehose] Failed to request crawl from relay")
          Nil
        }
      }
    })
  Nil
}
