/// XRPC com.atproto.sync.* handlers

import gleam_pds/context.{type Context}
import gleam_pds/crypto
import gleam_pds/web/response
import gleam/bytes_tree
import gleam/dynamic/decode
import gleam/int
import gleam/option
import gleam/json
import gleam/list
import gleam/result
import sqlight
import wisp.{type Request, type Response}

@external(erlang, "gleam_pds_cbor_ffi", "json_to_cbor")
fn json_to_cbor(json: String) -> BitArray

@external(erlang, "gleam_pds_cbor_ffi", "build_repo_car")
fn build_repo_car(
  did: String,
  rev: String,
  records: List(#(String, BitArray)),
  private_key: BitArray,
) -> BitArray

@external(erlang, "gleam_pds_cbor_ffi", "cid_bytes_from_base32")
fn cid_bytes_from_base32(cid: String) -> BitArray

@external(erlang, "gleam_pds_cbor_ffi", "build_car_file")
fn build_car_file(root: BitArray, blocks: List(#(BitArray, BitArray))) -> BitArray

/// Gather the complete, importable block set reachable from a commit CID:
/// commit block + MST nodes + record leaf blocks (deduplicated, no orphans).
@external(erlang, "gleam_pds_firehose_ffi", "collect_repo_blocks")
fn collect_repo_blocks(
  db: sqlight.Connection,
  did: String,
  commit_cid: String,
) -> List(#(BitArray, BitArray))

pub fn get_repo(req: Request, ctx: Context) -> Response {
  let did =
    wisp.get_query(req)
    |> list.key_find("did")

  case did {
    Error(_) ->
      response.xrpc_error(400, "InvalidRequest", "Missing did parameter")
    Ok(repo_did) -> {
      // 1. Try to serve via a reachability walk from the head commit.
      let head_rev = case
        sqlight.query(
          "SELECT head, rev FROM repos WHERE did = ? LIMIT 1",
          ctx.db,
          [sqlight.text(repo_did)],
          {
            use head <- decode.field(0, decode.string)
            use rev <- decode.field(1, decode.string)
            decode.success(#(head, rev))
          },
        )
      {
        Ok([hr]) -> option.Some(hr)
        _ -> option.None
      }

      case head_rev {
        option.Some(#(head_cid, _rev)) -> {
          // Walk from the head commit: commit block + reachable MST nodes +
          // record leaf blocks only (no orphaned/superseded MST versions).
          let blocks = collect_repo_blocks(ctx.db, repo_did, head_cid)

          case list.is_empty(blocks) {
            False -> {
              let car = build_car_file(cid_bytes_from_base32(head_cid), blocks)
              wisp.response(200)
              |> wisp.set_header("content-type", "application/vnd.ipld.car")
              |> wisp.set_body(wisp.Bytes(bytes_tree.from_bit_array(car)))
            }
            True -> {
              // Fallback to table scan if walk yielded nothing (legacy repos).
              serve_repo_via_scan(repo_did, ctx)
            }
          }
        }
        option.None -> serve_repo_via_scan(repo_did, ctx)
      }
    }
  }
}

fn serve_repo_via_scan(repo_did: String, ctx: Context) -> Response {
  let row_decoder = {
    use cbor <- decode.field(0, decode.optional(decode.bit_array))
    use json <- decode.field(1, decode.string)
    use collection <- decode.field(2, decode.string)
    use rkey <- decode.field(3, decode.string)
    decode.success(#(cbor, json, collection, rkey))
  }
  let result =
    sqlight.query(
      "SELECT record_cbor, record, collection, rkey FROM records WHERE did = ?",
      ctx.db,
      [sqlight.text(repo_did)],
      row_decoder,
    )

  let key_result =
    sqlight.query(
      "SELECT signing_key_private FROM repos WHERE did = ? LIMIT 1",
      ctx.db,
      [sqlight.text(repo_did)],
      decode.at([0], decode.bit_array),
    )

  case result, key_result {
    Ok(records), Ok([private_key]) -> {
      let rev = crypto.generate_tid()
      let record_pairs =
        list.map(records, fn(rec) {
          let #(maybe_cbor, record_json, collection, rkey) = rec
          let path = collection <> "/" <> rkey
          let data = case maybe_cbor {
            option.Some(cbor) -> cbor
            option.None -> json_to_cbor(record_json)
          }
          #(path, data)
        })

      let car = build_repo_car(repo_did, rev, record_pairs, private_key)

      wisp.response(200)
      |> wisp.set_header("content-type", "application/vnd.ipld.car")
      |> wisp.set_body(wisp.Bytes(bytes_tree.from_bit_array(car)))
    }
    _, _ -> {
      let rev = crypto.generate_tid()
      let car = build_repo_car(repo_did, rev, [], <<>>)
      wisp.response(200)
      |> wisp.set_header("content-type", "application/vnd.ipld.car")
      |> wisp.set_body(wisp.Bytes(bytes_tree.from_bit_array(car)))
    }
  }
}

/// com.atproto.sync.listRepos
pub fn list_repos(req: Request, ctx: Context) -> Response {
  let query = wisp.get_query(req)
  let limit =
    list.key_find(query, "limit")
    |> result.try(int.parse)
    |> result.unwrap(500)
  let cursor = list.key_find(query, "cursor") |> result.unwrap("")

  let row_decoder = {
    use d <- decode.field(0, decode.string)
    use h <- decode.field(1, decode.string)
    use head <- decode.field(2, decode.optional(decode.string))
    use rev <- decode.field(3, decode.optional(decode.string))
    use deactivated <- decode.field(4, decode.optional(decode.string))
    use takedown <- decode.field(5, decode.optional(decode.string))
    decode.success(#(d, h, head, rev, deactivated, takedown))
  }

  let result = case cursor {
    "" ->
      sqlight.query(
        "SELECT a.did, a.handle, r.head, r.rev, a.deactivated_at, a.takedown_ref
         FROM accounts a LEFT JOIN repos r ON a.did = r.did
         ORDER BY a.did LIMIT ?",
        ctx.db,
        [sqlight.int(limit)],
        row_decoder,
      )
    cur ->
      sqlight.query(
        "SELECT a.did, a.handle, r.head, r.rev, a.deactivated_at, a.takedown_ref
         FROM accounts a LEFT JOIN repos r ON a.did = r.did
         WHERE a.did > ? ORDER BY a.did LIMIT ?",
        ctx.db,
        [sqlight.text(cur), sqlight.int(limit)],
        row_decoder,
      )
  }

  case result {
    Ok(accounts) -> {
      let repos =
        list.map(accounts, fn(acc) {
          let #(did, _handle, maybe_head, maybe_rev, deactivated, takedown) =
            acc
          let head =
            option.unwrap(
              maybe_head,
              "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
            )
          let rev = option.unwrap(maybe_rev, crypto.generate_tid())
          let active = case deactivated, takedown {
            None, None -> True
            _, _ -> False
          }
          let status_fields = case deactivated, takedown {
            Some(_), _ -> [#("status", json.string("deactivated"))]
            None, Some(_) -> [#("status", json.string("takendown"))]
            None, None -> []
          }
          json.object(
            list.append(
              [
                #("did", json.string(did)),
                #("head", json.string(head)),
                #("rev", json.string(rev)),
                #("active", json.bool(active)),
              ],
              status_fields,
            ),
          )
        })

      let next_cursor = case list.length(accounts) == limit {
        True ->
          case list.last(accounts) {
            Ok(#(last_did, _, _, _, _, _)) -> json.string(last_did)
            Error(_) -> json.null()
          }
        False -> json.null()
      }

      response.json_response(
        200,
        json.object([
          #("repos", json.preprocessed_array(repos)),
          #("cursor", next_cursor),
        ]),
      )
    }
    Error(_) ->
      response.json_response(
        200,
        json.object([
          #("repos", json.preprocessed_array([])),
        ]),
      )
  }
}

/// com.atproto.sync.getLatestCommit
pub fn get_latest_commit(req: Request, ctx: Context) -> Response {
  let did =
    wisp.get_query(req)
    |> list.key_find("did")

  case did {
    Error(_) ->
      response.xrpc_error(400, "InvalidRequest", "Missing did parameter")
    Ok(repo_did) -> {
      let account =
        sqlight.query(
          "SELECT did FROM accounts WHERE did = ? LIMIT 1",
          ctx.db,
          [sqlight.text(repo_did)],
          decode.at([0], decode.string),
        )

      case account {
        Ok([_]) -> {
          let latest =
            sqlight.query(
              "SELECT head, rev FROM repos WHERE did = ? LIMIT 1",
              ctx.db,
              [sqlight.text(repo_did)],
              {
                use h <- decode.field(0, decode.optional(decode.string))
                use r <- decode.field(1, decode.optional(decode.string))
                decode.success(#(h, r))
              },
            )
          let #(cid, rev) = case latest {
            Ok([#(option.Some(c), option.Some(r))]) -> #(c, r)
            _ -> #("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi", crypto.generate_tid())
          }

          response.json_response(
            200,
            json.object([
              #("cid", json.string(cid)),
              #("rev", json.string(rev)),
            ]),
          )
        }
        _ ->
          response.xrpc_error(400, "RepoNotFound", "Repo not found: " <> repo_did)
      }
    }
  }
}

/// com.atproto.sync.getRepoStatus
pub fn get_repo_status(req: Request, ctx: Context) -> Response {
  let did =
    wisp.get_query(req)
    |> list.key_find("did")

  case did {
    Error(_) ->
      response.xrpc_error(400, "InvalidRequest", "Missing did parameter")
    Ok(repo_did) -> {
      let account =
        sqlight.query(
          "SELECT did FROM accounts WHERE did = ? LIMIT 1",
          ctx.db,
          [sqlight.text(repo_did)],
          decode.at([0], decode.string),
        )

      case account {
        Ok([_]) -> {
          let latest =
            sqlight.query(
              "SELECT rev FROM repos WHERE did = ? LIMIT 1",
              ctx.db,
              [sqlight.text(repo_did)],
              decode.at([0], decode.optional(decode.string)),
            )
          let rev = case latest {
            Ok([option.Some(r)]) -> r
            _ -> crypto.generate_tid()
          }
          response.json_response(
            200,
            json.object([
              #("did", json.string(repo_did)),
              #("active", json.bool(True)),
              #("rev", json.string(rev)),
            ]),
          )
        }
        _ ->
          response.xrpc_error(400, "RepoNotFound", "Repo not found: " <> repo_did)
      }
    }
  }
}

/// com.atproto.sync.getRecord
pub fn get_record(req: Request, ctx: Context) -> Response {
  let query = wisp.get_query(req)
  let did = list.key_find(query, "did")
  let collection = list.key_find(query, "collection")
  let rkey = list.key_find(query, "rkey")

  case did, collection, rkey {
    Ok(repo_did), Ok(coll), Ok(rk) -> {
      // Verify the repo exists
      let key_result =
        sqlight.query(
          "SELECT signing_key_private FROM repos WHERE did = ? LIMIT 1",
          ctx.db,
          [sqlight.text(repo_did)],
          decode.at([0], decode.bit_array),
        )

      case key_result {
        Ok([private_key]) -> {
          // Verify the specific record exists
          let record_exists =
            sqlight.query(
              "SELECT 1 FROM records WHERE did = ? AND collection = ? AND rkey = ? LIMIT 1",
              ctx.db,
              [sqlight.text(repo_did), sqlight.text(coll), sqlight.text(rk)],
              decode.at([0], decode.int),
            )

          case record_exists {
            Ok([_]) -> {
              // Record exists — build full repo CAR (same as get_repo)
              let row_decoder = {
                use cbor <- decode.field(0, decode.optional(decode.bit_array))
                use json <- decode.field(1, decode.string)
                use c <- decode.field(2, decode.string)
                use r <- decode.field(3, decode.string)
                decode.success(#(cbor, json, c, r))
              }
              let result =
                sqlight.query(
                  "SELECT record_cbor, record, collection, rkey FROM records WHERE did = ? ORDER BY collection, rkey",
                  ctx.db,
                  [sqlight.text(repo_did)],
                  row_decoder,
                )

              case result {
                Ok(records) -> {
                  let rev = crypto.generate_tid()
                  let record_pairs =
                    list.map(records, fn(rec) {
                      let #(maybe_cbor, record_json, record_coll, record_rkey) = rec
                      let path = record_coll <> "/" <> record_rkey
                      let data = case maybe_cbor {
                        option.Some(cbor) -> cbor
                        option.None -> json_to_cbor(record_json)
                      }
                      #(path, data)
                    })

                  let car = build_repo_car(repo_did, rev, record_pairs, private_key)

                  wisp.response(200)
                  |> wisp.set_header("content-type", "application/vnd.ipld.car")
                  |> wisp.set_body(wisp.Bytes(bytes_tree.from_bit_array(car)))
                }
                Error(_) ->
                  response.xrpc_error(404, "RecordNotFound", "Record not found")
              }
            }
            _ ->
              response.xrpc_error(404, "RecordNotFound", "Record not found")
          }
        }
        _ ->
          response.xrpc_error(404, "RepoNotFound", "Repo not found: " <> repo_did)
      }
    }
    _, _, _ ->
      response.xrpc_error(
        400,
        "InvalidRequest",
        "Missing required parameter: did, collection, and rkey are all required",
      )
  }
}

pub fn get_blob(req: Request, ctx: Context) -> Response {
  let query = wisp.get_query(req)
  let did = list.key_find(query, "did")
  let cid = list.key_find(query, "cid")

  case did, cid {
    Ok(repo_did), Ok(blob_cid) -> {
      let result =
        sqlight.query(
          "SELECT data, mime_type FROM blobs WHERE cid = ? AND did = ? LIMIT 1",
          ctx.db,
          [sqlight.text(blob_cid), sqlight.text(repo_did)],
          {
            use d <- decode.field(0, decode.bit_array)
            use m <- decode.field(1, decode.string)
            decode.success(#(d, m))
          },
        )

      case result {
        Ok([#(data, mime_type)]) ->
          wisp.response(200)
          |> wisp.set_header("content-type", mime_type)
          |> wisp.set_body(wisp.Bytes(bytes_tree.from_bit_array(data)))
        _ -> response.xrpc_error(404, "BlobNotFound", "Blob not found")
      }
    }
    _, _ ->
      response.xrpc_error(
        400,
        "InvalidRequest",
        "Missing did or cid parameter",
      )
  }
}

/// com.atproto.sync.listBlobs - list the blob CIDs held for a repo.
/// (The `since` rev filter is not applied; the full blob set is returned.)
pub fn list_blobs(req: Request, ctx: Context) -> Response {
  let query = wisp.get_query(req)
  case list.key_find(query, "did") {
    Error(_) ->
      response.xrpc_error(400, "InvalidRequest", "Missing did parameter")
    Ok(repo_did) -> {
      let limit =
        list.key_find(query, "limit")
        |> result.try(int.parse)
        |> result.unwrap(500)
      let cursor = list.key_find(query, "cursor") |> result.unwrap("")

      let result = case cursor {
        "" ->
          sqlight.query(
            "SELECT cid FROM blobs WHERE did = ? ORDER BY cid LIMIT ?",
            ctx.db,
            [sqlight.text(repo_did), sqlight.int(limit)],
            decode.at([0], decode.string),
          )
        cur ->
          sqlight.query(
            "SELECT cid FROM blobs WHERE did = ? AND cid > ? ORDER BY cid LIMIT ?",
            ctx.db,
            [sqlight.text(repo_did), sqlight.text(cur), sqlight.int(limit)],
            decode.at([0], decode.string),
          )
      }

      case result {
        Ok(cids) -> {
          let next_cursor = case list.length(cids) == limit {
            True ->
              case list.last(cids) {
                Ok(last) -> json.string(last)
                Error(_) -> json.null()
              }
            False -> json.null()
          }
          response.json_response(
            200,
            json.object([
              #("cids", json.array(cids, json.string)),
              #("cursor", next_cursor),
            ]),
          )
        }
        _ ->
          response.json_response(
            200,
            json.object([
              #("cids", json.array([], json.string)),
              #("cursor", json.null()),
            ]),
          )
      }
    }
  }
}
