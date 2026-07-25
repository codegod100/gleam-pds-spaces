/// XRPC com.atproto.repo.* handlers

import gleam_pds/context.{type Context}
import gleam_pds/crypto
import gleam_pds/db
import gleam_pds/firehose
import gleam_pds/web/response
import gleam_pds/xrpc/server
import gleam/bit_array
import gleam/dynamic/decode
import gleam/erlang/process
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import sqlight
import wisp.{type Request, type Response}

pub fn describe_repo(req: Request, ctx: Context) -> Response {
  let repo_did =
    wisp.get_query(req)
    |> list.key_find("repo")

  case repo_did {
    Error(_) ->
      response.xrpc_error(400, "InvalidRequest", "Missing repo parameter")
    Ok(did) -> {
      let result =
        sqlight.query(
          "SELECT a.handle FROM accounts a WHERE a.did = ? LIMIT 1",
          ctx.db,
          [sqlight.text(did)],
          decode.at([0], decode.string),
        )

      case result {
        Ok([handle]) -> {
          case server.get_public_key_for_did(did, ctx) {
            Error(_) ->
              response.xrpc_error(
                500,
                "InternalError",
                "Missing signing key for repo",
              )
            Ok(pk) -> {
              let collections_result =
                sqlight.query(
                  "SELECT DISTINCT collection FROM records WHERE did = ?",
                  ctx.db,
                  [sqlight.text(did)],
                  decode.at([0], decode.string),
                )
              let collections = case collections_result {
                Ok(colls) -> colls
                Error(_) -> []
              }
              let did_doc =
                server.build_did_doc(did, handle, pk, ctx.config.public_url)
              response.json_response(
                200,
                json.object([
                  #("handle", json.string(handle)),
                  #("did", json.string(did)),
                  #("didDoc", did_doc),
                  #("collections", json.array(collections, json.string)),
                  #("handleIsCorrect", json.bool(True)),
                ]),
              )
            }
          }
        }
        _ -> response.xrpc_error(400, "RepoNotFound", "Repo not found")
      }
    }
  }
}

pub fn get_record(req: Request, ctx: Context) -> Response {
  let query = wisp.get_query(req)
  let repo_did = list.key_find(query, "repo")
  let collection = list.key_find(query, "collection")
  let rkey = list.key_find(query, "rkey")

  case repo_did, collection, rkey {
    Ok(did), Ok(coll), Ok(key) -> {
      let uri = "at://" <> did <> "/" <> coll <> "/" <> key
      let row_decoder = {
        use r <- decode.field(0, decode.string)
        use c <- decode.field(1, decode.string)
        decode.success(#(r, c))
      }
      let result =
        sqlight.query(
          "SELECT record, cid FROM records WHERE uri = ? LIMIT 1",
          ctx.db,
          [sqlight.text(uri)],
          row_decoder,
        )

      case result {
        Ok([#(record_json, cid)]) ->
          wisp.response(200)
          |> wisp.set_header("content-type", "application/json")
          |> wisp.set_body(wisp.Text(
            "{\"uri\":\"" <> uri <> "\",\"cid\":\"" <> cid
            <> "\",\"value\":" <> record_json <> "}",
          ))
        _ -> response.xrpc_error(400, "RecordNotFound", "Record not found")
      }
    }
    _, _, _ ->
      response.xrpc_error(
        400,
        "InvalidRequest",
        "Missing repo, collection, or rkey",
      )
  }
}

pub fn list_records(req: Request, ctx: Context) -> Response {
  let query = wisp.get_query(req)
  let repo_did = list.key_find(query, "repo")
  let collection = list.key_find(query, "collection")
  let limit =
    list.key_find(query, "limit")
    |> result.try(int.parse)
    |> result.unwrap(50)
  let cursor = list.key_find(query, "cursor") |> result.unwrap("")

  case repo_did, collection {
    Ok(did), Ok(coll) -> {
      let row_decoder = {
        use u <- decode.field(0, decode.string)
        use c <- decode.field(1, decode.string)
        use r <- decode.field(2, decode.string)
        decode.success(#(u, c, r))
      }
      let result = case cursor {
        "" ->
          sqlight.query(
            "SELECT uri, cid, record FROM records WHERE did = ? AND collection = ? ORDER BY rkey ASC LIMIT ?",
            ctx.db,
            [
              sqlight.text(did),
              sqlight.text(coll),
              sqlight.int(limit),
            ],
            row_decoder,
          )
        cur ->
          sqlight.query(
            "SELECT uri, cid, record FROM records WHERE did = ? AND collection = ? AND rkey > ? ORDER BY rkey ASC LIMIT ?",
            ctx.db,
            [
              sqlight.text(did),
              sqlight.text(coll),
              sqlight.text(cur),
              sqlight.int(limit),
            ],
            row_decoder,
          )
      }

      case result {
        Ok(records) -> {
          let record_json =
            list.map(records, fn(rec) {
              let #(uri, cid, value_json) = rec
              "{\"uri\":\"" <> uri <> "\",\"cid\":\"" <> cid
              <> "\",\"value\":" <> value_json <> "}"
            })
          let records_str = "[" <> string.join(record_json, ",") <> "]"

          // Build cursor from the last record's rkey
          let cursor_str = case list.length(records) == limit {
            True -> {
              case list.last(records) {
                Ok(#(last_uri, _, _)) -> {
                  // Extract rkey from uri (at://did/collection/rkey)
                  let parts = string.split(last_uri, "/")
                  case list.last(parts) {
                    Ok(rkey) -> ",\"cursor\":\"" <> rkey <> "\""
                    Error(_) -> ""
                  }
                }
                Error(_) -> ""
              }
            }
            False -> ""
          }

          wisp.response(200)
          |> wisp.set_header("content-type", "application/json")
          |> wisp.set_body(wisp.Text(
            "{\"records\":" <> records_str <> cursor_str <> "}",
          ))
        }
        Error(_) ->
          response.json_response(
            200,
            json.object([#("records", json.array([], json.string))]),
          )
      }
    }
    _, _ ->
      response.xrpc_error(
        400,
        "InvalidRequest",
        "Missing repo or collection parameter",
      )
  }
}

pub fn create_record(req: Request, ctx: Context) -> Response {
  case server.get_auth_did(req, ctx) {
    Error(resp) -> resp
    Ok(user_did) -> {
      use body <- wisp.require_json(req)

      let decoder = {
        use repo <- decode.field("repo", decode.string)
        use collection <- decode.field("collection", decode.string)
        use rkey <- decode.optional_field(
          "rkey",
          None,
          decode.optional(decode.string),
        )
        use swap_commit <- decode.optional_field(
          "swapCommit",
          None,
          decode.optional(decode.string),
        )
        decode.success(#(repo, collection, rkey, swap_commit))
      }

      case decode.run(body, decoder) {
        Error(_) ->
          response.xrpc_error(400, "InvalidRequest", "Invalid request body")
        Ok(#(repo, collection, maybe_rkey, swap_commit)) -> {
          case repo == user_did {
            False ->
              response.xrpc_error(
                403,
                "AuthorizationError",
                "Not authorized for this repo",
              )
            True -> {
              // Capture previous repo state for optimistic concurrency and the
              // inductive firehose (since / prevData).
              let #(prev_commit_cid, prev_rev) = repo_head_rev(ctx, user_did)
              case swap_commit {
                Some(sc) if sc != prev_commit_cid ->
                  response.xrpc_error(
                    400,
                    "InvalidSwap",
                    "swapCommit CID does not match current head",
                  )
                _ -> {
                  let rkey = case maybe_rkey {
                    Some(k) -> k
                    None -> crypto.generate_tid()
                  }
                  let uri =
                    "at://" <> user_did <> "/" <> collection <> "/" <> rkey

                  let record_json = extract_record_json(body)
                  let record_cbor = encode_record_cbor(body)
                  let cid = crypto.compute_cid(record_cbor)

                  let result =
                    sqlight.query(
                      "INSERT INTO records (uri, did, collection, rkey, record, cid, record_cbor) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING uri",
                      ctx.db,
                      [
                        sqlight.text(uri),
                        sqlight.text(user_did),
                        sqlight.text(collection),
                        sqlight.text(rkey),
                        sqlight.text(record_json),
                        sqlight.text(cid),
                        sqlight.blob(record_cbor),
                      ],
                      decode.at([0], decode.string),
                    )

                  case result {
                    Ok(_) -> {
                      // Record leaf must be in `blocks` for CAR walks.
                      insert_record_block(ctx, user_did, cid, record_cbor)
                      let rev = crypto.generate_tid()
                      let commit_cid =
                        update_repo_head_incremental(
                          ctx,
                          user_did,
                          rev,
                          collection <> "/" <> rkey,
                          cid,
                          "create",
                        )
                      // Firehose broadcast + relay crawl (throttled by actor).
                      let _ = process.spawn(fn() {
                        process.send(
                          ctx.firehose,
                          firehose.Emit(firehose.CommitEvent(
                            did: user_did,
                            collection: collection,
                            rkey: rkey,
                            action: "create",
                            record_cbor: record_cbor,
                            cid: cid,
                            rev: rev,
                            commit_cid: commit_cid,
                            since: prev_rev,
                            prev_record_cid: "",
                            prev_commit_cid: prev_commit_cid,
                          )),
                        )
                        process.send(
                          ctx.firehose,
                          firehose.RequestCrawl(ctx.config),
                        )
                      })
                      response.json_response(
                        200,
                        json.object([
                          #("uri", json.string(uri)),
                          #("cid", json.string(cid)),
                          #("commit", json.object([
                            #("cid", json.string(commit_cid)),
                            #("rev", json.string(rev)),
                          ])),
                          #("validationStatus", json.string("valid")),
                        ]),
                      )
                    }
                    Error(_) ->
                      response.xrpc_error(
                        400,
                        "InvalidRequest",
                        "Record already exists at " <> uri,
                      )
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}

@external(erlang, "gleam_pds_repo_ffi", "extract_record_json")
fn extract_record_json(body: decode.Dynamic) -> String

/// Encode the "record" field from a request body to DAG-CBOR bytes
@external(erlang, "gleam_pds_cbor_ffi", "encode_record_cbor")
fn encode_record_cbor(body: decode.Dynamic) -> BitArray

/// Parse a JSON string and encode as DAG-CBOR bytes
@external(erlang, "gleam_pds_cbor_ffi", "json_to_cbor")
fn json_to_cbor(json: String) -> BitArray

/// Decode DAG-CBOR bytes to a JSON string
@external(erlang, "gleam_pds_cbor_ffi", "cbor_to_json")
fn cbor_to_json(cbor: BitArray) -> String

@external(erlang, "gleam_pds_mst_ffi", "mst_upsert")
fn mst_upsert(db: sqlight.Connection, did: String, key: String, value_cid: String) -> String

@external(erlang, "gleam_pds_mst_ffi", "mst_delete")
fn mst_delete(db: sqlight.Connection, did: String, key: String) -> String

@external(erlang, "gleam_pds_mst_ffi", "sign_and_store_commit")
fn sign_and_store_commit(db: sqlight.Connection, did: String, rev: String, root_cid: String, private_key: BitArray) -> String

fn update_repo_head_incremental(ctx: Context, did: String, rev: String, key: String, cid: String, action: String) -> String {
  let private_key = case
    sqlight.query(
      "SELECT signing_key_private FROM repos WHERE did = ? LIMIT 1",
      ctx.db,
      [sqlight.text(did)],
      decode.at([0], decode.bit_array),
    )
  {
    Ok([k]) -> k
    _ -> <<>>
  }

  let root_cid = case action {
    "create" | "update" -> mst_upsert(ctx.db, did, key, cid)
    "delete" -> mst_delete(ctx.db, did, key)
    _ -> ""
  }

  sign_and_store_commit(ctx.db, did, rev, root_cid, private_key)
}

/// Store a record's CBOR block in the `blocks` table so getRepo and firehose
/// CARs (which walk the MST from the head commit) can find the leaf blocks.
fn insert_record_block(
  ctx: Context,
  did: String,
  cid: String,
  cbor: BitArray,
) -> Nil {
  let _ =
    sqlight.query(
      "INSERT OR REPLACE INTO blocks (cid, did, data) VALUES (?, ?, ?)",
      ctx.db,
      [sqlight.text(cid), sqlight.text(did), sqlight.blob(cbor)],
      decode.at([0], decode.int),
    )
  Nil
}

/// Current head commit CID and rev of a repo ("" when absent).
fn repo_head_rev(ctx: Context, did: String) -> #(String, String) {
  case
    sqlight.query(
      "SELECT head, rev FROM repos WHERE did = ? LIMIT 1",
      ctx.db,
      [sqlight.text(did)],
      {
        use h <- decode.field(0, decode.optional(decode.string))
        use r <- decode.field(1, decode.optional(decode.string))
        decode.success(#(h, r))
      },
    )
  {
    Ok([#(Some(h), Some(r))]) -> #(h, r)
    Ok([#(Some(h), None)]) -> #(h, "")
    Ok([#(None, Some(r))]) -> #("", r)
    _ -> #("", "")
  }
}

/// Optimistic-concurrency check: passes when no swap was requested, or when the
/// requested swap CID matches the current value.
fn check_swap(swap: option.Option(String), current: String) -> Bool {
  case swap {
    None -> True
    Some(v) -> v == current
  }
}

/// Current CID of the record at `uri` ("" when absent).
fn current_record_cid(ctx: Context, uri: String) -> String {
  case
    sqlight.query(
      "SELECT cid FROM records WHERE uri = ? LIMIT 1",
      ctx.db,
      [sqlight.text(uri)],
      decode.at([0], decode.string),
    )
  {
    Ok([c]) -> c
    _ -> ""
  }
}

pub fn put_record(req: Request, ctx: Context) -> Response {
  case server.get_auth_did(req, ctx) {
    Error(resp) -> resp
    Ok(user_did) -> {
      use body <- wisp.require_json(req)

      let decoder = {
        use repo <- decode.field("repo", decode.string)
        use collection <- decode.field("collection", decode.string)
        use rkey <- decode.field("rkey", decode.string)
        use swap_commit <- decode.optional_field(
          "swapCommit",
          None,
          decode.optional(decode.string),
        )
        use swap_record <- decode.optional_field(
          "swapRecord",
          None,
          decode.optional(decode.string),
        )
        decode.success(#(repo, collection, rkey, swap_commit, swap_record))
      }

      case decode.run(body, decoder) {
        Error(_) ->
          response.xrpc_error(400, "InvalidRequest", "Invalid request body")
        Ok(#(repo, collection, rkey, swap_commit, swap_record)) -> {
          case repo == user_did {
            False ->
              response.xrpc_error(
                403,
                "AuthorizationError",
                "Not authorized",
              )
            True -> {
              let uri =
                "at://" <> user_did <> "/" <> collection <> "/" <> rkey
              let #(prev_commit_cid, prev_rev) = repo_head_rev(ctx, user_did)
              // "" means the record does not currently exist.
              let prev_record_cid = current_record_cid(ctx, uri)

              case
                check_swap(swap_commit, prev_commit_cid),
                check_swap(swap_record, prev_record_cid)
              {
                False, _ ->
                  response.xrpc_error(
                    400,
                    "InvalidSwap",
                    "swapCommit CID does not match current head",
                  )
                _, False ->
                  response.xrpc_error(
                    400,
                    "InvalidSwap",
                    "swapRecord CID does not match current record",
                  )
                _, _ -> {
                  let record_json = extract_record_json(body)
                  let record_cbor = encode_record_cbor(body)
                  let cid = crypto.compute_cid(record_cbor)

                  let _ =
                    sqlight.query(
                      "INSERT OR REPLACE INTO records (uri, did, collection, rkey, record, cid, record_cbor) VALUES (?, ?, ?, ?, ?, ?, ?)",
                      ctx.db,
                      [
                        sqlight.text(uri),
                        sqlight.text(user_did),
                        sqlight.text(collection),
                        sqlight.text(rkey),
                        sqlight.text(record_json),
                        sqlight.text(cid),
                        sqlight.blob(record_cbor),
                      ],
                      decode.at([0], decode.string),
                    )
                  insert_record_block(ctx, user_did, cid, record_cbor)

                  let rev = crypto.generate_tid()
                  let commit_cid =
                    update_repo_head_incremental(
                      ctx,
                      user_did,
                      rev,
                      collection <> "/" <> rkey,
                      cid,
                      "update",
                    )
                  let _ = process.spawn(fn() {
                    process.send(
                      ctx.firehose,
                      firehose.Emit(firehose.CommitEvent(
                        did: user_did,
                        collection: collection,
                        rkey: rkey,
                        action: "update",
                        record_cbor: record_cbor,
                        cid: cid,
                        rev: rev,
                        commit_cid: commit_cid,
                        since: prev_rev,
                        prev_record_cid: prev_record_cid,
                        prev_commit_cid: prev_commit_cid,
                      )),
                    )
                    process.send(
                      ctx.firehose,
                      firehose.RequestCrawl(ctx.config),
                    )
                  })
                  response.json_response(
                    200,
                    json.object([
                      #("uri", json.string(uri)),
                      #("cid", json.string(cid)),
                      #("commit", json.object([
                        #("cid", json.string(commit_cid)),
                        #("rev", json.string(rev)),
                      ])),
                      #("validationStatus", json.string("valid")),
                    ]),
                  )
                }
              }
            }
          }
        }
      }
    }
  }
}

pub fn delete_record(req: Request, ctx: Context) -> Response {
  case server.get_auth_did(req, ctx) {
    Error(resp) -> resp
    Ok(user_did) -> {
      use body <- wisp.require_json(req)

      let decoder = {
        use repo <- decode.field("repo", decode.string)
        use collection <- decode.field("collection", decode.string)
        use rkey <- decode.field("rkey", decode.string)
        use swap_commit <- decode.optional_field(
          "swapCommit",
          None,
          decode.optional(decode.string),
        )
        use swap_record <- decode.optional_field(
          "swapRecord",
          None,
          decode.optional(decode.string),
        )
        decode.success(#(repo, collection, rkey, swap_commit, swap_record))
      }

      case decode.run(body, decoder) {
        Error(_) ->
          response.xrpc_error(400, "InvalidRequest", "Invalid request body")
        Ok(#(repo, collection, rkey, swap_commit, swap_record)) -> {
          case repo == user_did {
            False ->
              response.xrpc_error(
                403,
                "AuthorizationError",
                "Not authorized",
              )
            True -> {
              let uri =
                "at://" <> user_did <> "/" <> collection <> "/" <> rkey
              let #(prev_commit_cid, prev_rev) = repo_head_rev(ctx, user_did)
              let prev_record_cid = current_record_cid(ctx, uri)

              case
                check_swap(swap_commit, prev_commit_cid),
                check_swap(swap_record, prev_record_cid)
              {
                False, _ ->
                  response.xrpc_error(
                    400,
                    "InvalidSwap",
                    "swapCommit CID does not match current head",
                  )
                _, False ->
                  response.xrpc_error(
                    400,
                    "InvalidSwap",
                    "swapRecord CID does not match current record",
                  )
                _, _ -> {
                  let _ =
                    sqlight.query(
                      "DELETE FROM records WHERE uri = ? AND did = ?",
                      ctx.db,
                      [sqlight.text(uri), sqlight.text(user_did)],
                      decode.at([0], decode.string),
                    )

                  let del_rev = crypto.generate_tid()
                  let del_commit_cid =
                    update_repo_head_incremental(
                      ctx,
                      user_did,
                      del_rev,
                      collection <> "/" <> rkey,
                      "",
                      "delete",
                    )
                  let _ = process.spawn(fn() {
                    process.send(
                      ctx.firehose,
                      firehose.Emit(firehose.CommitEvent(
                        did: user_did,
                        collection: collection,
                        rkey: rkey,
                        action: "delete",
                        record_cbor: <<>>,
                        // null op.cid; no garbage block in the CAR.
                        cid: "",
                        rev: del_rev,
                        commit_cid: del_commit_cid,
                        since: prev_rev,
                        prev_record_cid: prev_record_cid,
                        prev_commit_cid: prev_commit_cid,
                      )),
                    )
                    process.send(
                      ctx.firehose,
                      firehose.RequestCrawl(ctx.config),
                    )
                  })

                  wisp.ok()
                }
              }
            }
          }
        }
      }
    }
  }
}

pub fn upload_blob(req: Request, ctx: Context) -> Response {
  case server.get_auth_did(req, ctx) {
    Error(resp) -> resp
    Ok(user_did) -> {
      use body <- wisp.require_bit_array_body(req)

      let size = bit_array.byte_size(body)
      case size > db.max_blob_size {
        True ->
          response.xrpc_error(
            413,
            "BlobTooLarge",
            "Blob exceeds maximum allowed size",
          )
        False -> {
          let content_type =
            list.key_find(req.headers, "content-type")
            |> result.unwrap("application/octet-stream")

          let cid = crypto.compute_blob_cid(body)

      let _ =
        sqlight.query(
          "INSERT OR REPLACE INTO blobs (cid, did, mime_type, size, data) VALUES (?, ?, ?, ?, ?)",
          ctx.db,
          [
            sqlight.text(cid),
            sqlight.text(user_did),
            sqlight.text(content_type),
            sqlight.int(size),
            sqlight.blob(body),
          ],
          decode.at([0], decode.string),
        )

      response.json_response(
        200,
        json.object([
          #(
            "blob",
            json.object([
              #("$type", json.string("blob")),
              #(
                "ref",
                json.object([#("$link", json.string(cid))]),
              ),
              #("mimeType", json.string(content_type)),
              #("size", json.int(size)),
            ]),
          ),
        ]),
      )
        }
      }
    }
  }
}

/// com.atproto.repo.applyWrites - batch write operations
pub fn apply_writes(req: Request, ctx: Context) -> Response {
  case server.get_auth_did(req, ctx) {
    Error(resp) -> resp
    Ok(user_did) -> {
      use body <- wisp.require_json(req)

      let decoder = {
        use repo <- decode.field("repo", decode.string)
        use swap_commit <- decode.optional_field(
          "swapCommit",
          None,
          decode.optional(decode.string),
        )
        decode.success(#(repo, swap_commit))
      }

      case decode.run(body, decoder) {
        Error(_) ->
          response.xrpc_error(400, "InvalidRequest", "Invalid request body")
        Ok(#(repo, swap_commit)) -> {
          case repo == user_did {
            False ->
              response.xrpc_error(
                403,
                "AuthorizationError",
                "Not authorized for this repo",
              )
            True -> {
              let #(cur_head, _cur_rev) = repo_head_rev(ctx, user_did)
              case check_swap(swap_commit, cur_head) {
                False ->
                  response.xrpc_error(
                    400,
                    "InvalidSwap",
                    "swapCommit CID does not match current head",
                  )
                True -> {
              // Process each write operation
              let writes = extract_writes(body)
              let results = list.map(writes, fn(write) {
                apply_single_write(user_did, write, ctx)
              })
              let _rev = crypto.generate_tid()
              // We return the head from the database, which is already updated by apply_single_write
              let commit_cid = case
                sqlight.query(
                  "SELECT head FROM repos WHERE did = ? LIMIT 1",
                  ctx.db,
                  [sqlight.text(user_did)],
                  decode.at([0], decode.string),
                )
              {
                Ok([h]) -> h
                _ -> ""
              }
              let last_rev = case
                sqlight.query(
                  "SELECT rev FROM repos WHERE did = ? LIMIT 1",
                  ctx.db,
                  [sqlight.text(user_did)],
                  decode.at([0], decode.string),
                )
              {
                Ok([r]) -> r
                _ -> ""
              }
              response.json_response(
                200,
                json.object([
                  #("commit", json.object([
                    #("cid", json.string(commit_cid)),
                    #("rev", json.string(last_rev)),
                  ])),
                  #("results", json.preprocessed_array(results)),
                ]),
              )
            }
              }
            }
          }
        }
      }
    }
  }
}

type WriteOp {
  CreateWrite(collection: String, rkey: String, record_json: String)
  UpdateWrite(collection: String, rkey: String, record_json: String)
  DeleteWrite(collection: String, rkey: String)
}

@external(erlang, "gleam_pds_repo_ffi", "extract_writes")
fn extract_writes(body: decode.Dynamic) -> List(WriteOp)

fn apply_single_write(
  user_did: String,
  write: WriteOp,
  ctx: Context,
) -> json.Json {
  case write {
    CreateWrite(collection, rkey, record_json) -> {
      let rkey = case rkey {
        "" -> crypto.generate_tid()
        k -> k
      }
      let uri = "at://" <> user_did <> "/" <> collection <> "/" <> rkey
      let #(prev_commit_cid, prev_rev) = repo_head_rev(ctx, user_did)
      let record_cbor = json_to_cbor(record_json)
      let cid = crypto.compute_cid(record_cbor)
      let _ =
        sqlight.query(
          "INSERT OR REPLACE INTO records (uri, did, collection, rkey, record, cid, record_cbor) VALUES (?, ?, ?, ?, ?, ?, ?)",
          ctx.db,
          [
            sqlight.text(uri),
            sqlight.text(user_did),
            sqlight.text(collection),
            sqlight.text(rkey),
            sqlight.text(record_json),
            sqlight.text(cid),
            sqlight.blob(record_cbor),
          ],
          decode.at([0], decode.string),
        )
      insert_record_block(ctx, user_did, cid, record_cbor)
      // Emit firehose event with real commit CID
      let rev = crypto.generate_tid()
      let commit_cid = update_repo_head_incremental(ctx, user_did, rev, collection <> "/" <> rkey, cid, "create")
      process.send(
        ctx.firehose,
        firehose.Emit(firehose.CommitEvent(
          did: user_did,
          collection: collection,
          rkey: rkey,
          action: "create",
          record_cbor: record_cbor,
          cid: cid,
          rev: rev,
          commit_cid: commit_cid,
          since: prev_rev,
          prev_record_cid: "",
          prev_commit_cid: prev_commit_cid,
        )),
      )
      process.send(ctx.firehose, firehose.RequestCrawl(ctx.config))
      json.object([
        #("$type", json.string("com.atproto.repo.applyWrites#createResult")),
        #("uri", json.string(uri)),
        #("cid", json.string(cid)),
        #("validationStatus", json.string("valid")),
      ])
    }
    UpdateWrite(collection, rkey, record_json) -> {
      let uri = "at://" <> user_did <> "/" <> collection <> "/" <> rkey
      let #(prev_commit_cid, prev_rev) = repo_head_rev(ctx, user_did)
      let prev_record_cid = current_record_cid(ctx, uri)
      let record_cbor = json_to_cbor(record_json)
      let cid = crypto.compute_cid(record_cbor)
      let _ =
        sqlight.query(
          "INSERT OR REPLACE INTO records (uri, did, collection, rkey, record, cid, record_cbor) VALUES (?, ?, ?, ?, ?, ?, ?)",
          ctx.db,
          [
            sqlight.text(uri),
            sqlight.text(user_did),
            sqlight.text(collection),
            sqlight.text(rkey),
            sqlight.text(record_json),
            sqlight.text(cid),
            sqlight.blob(record_cbor),
          ],
          decode.at([0], decode.string),
        )
      insert_record_block(ctx, user_did, cid, record_cbor)
      // Emit firehose event with real commit CID
      let rev = crypto.generate_tid()
      let commit_cid = update_repo_head_incremental(ctx, user_did, rev, collection <> "/" <> rkey, cid, "update")
      process.send(
        ctx.firehose,
        firehose.Emit(firehose.CommitEvent(
          did: user_did,
          collection: collection,
          rkey: rkey,
          action: "update",
          record_cbor: record_cbor,
          cid: cid,
          rev: rev,
          commit_cid: commit_cid,
          since: prev_rev,
          prev_record_cid: prev_record_cid,
          prev_commit_cid: prev_commit_cid,
        )),
      )
      process.send(ctx.firehose, firehose.RequestCrawl(ctx.config))
      json.object([
        #("$type", json.string("com.atproto.repo.applyWrites#updateResult")),
        #("uri", json.string(uri)),
        #("cid", json.string(cid)),
        #("validationStatus", json.string("valid")),
      ])
    }
    DeleteWrite(collection, rkey) -> {
      let uri = "at://" <> user_did <> "/" <> collection <> "/" <> rkey
      let #(prev_commit_cid, prev_rev) = repo_head_rev(ctx, user_did)
      let prev_record_cid = current_record_cid(ctx, uri)
      let _ =
        sqlight.query(
          "DELETE FROM records WHERE uri = ? AND did = ?",
          ctx.db,
          [sqlight.text(uri), sqlight.text(user_did)],
          decode.at([0], decode.string),
        )
      // Emit firehose event with real commit CID
      let del_rev = crypto.generate_tid()
      let del_commit_cid = update_repo_head_incremental(ctx, user_did, del_rev, collection <> "/" <> rkey, "", "delete")
      process.send(
        ctx.firehose,
        firehose.Emit(firehose.CommitEvent(
          did: user_did,
          collection: collection,
          rkey: rkey,
          action: "delete",
          record_cbor: <<>>,
          cid: "",
          rev: del_rev,
          commit_cid: del_commit_cid,
          since: prev_rev,
          prev_record_cid: prev_record_cid,
          prev_commit_cid: prev_commit_cid,
        )),
      )
      process.send(ctx.firehose, firehose.RequestCrawl(ctx.config))
      json.object([
        #("$type", json.string("com.atproto.repo.applyWrites#deleteResult")),
      ])
    }
  }
}

