/// XRPC com.atproto.identity.* handlers

import gleam_pds/context.{type Context}
import gleam_pds/did as did_module
import gleam_pds/firehose
import gleam_pds/plc
import gleam/erlang/process
import gleam_pds/web/response
import gleam_pds/xrpc/server
import gleam/dynamic
import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/httpc
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import sqlight
import wisp.{type Request, type Response}

@external(erlang, "gleam_pds_crypto_ffi", "public_key_to_did_key")
fn public_key_to_did_key(public_key: BitArray) -> String

// ---------------------------------------------------------------------------
// resolveHandle (existing)
// ---------------------------------------------------------------------------

pub fn resolve_handle(req: Request, ctx: Context) -> Response {
  let handle =
    wisp.get_query(req)
    |> list.key_find("handle")

  case handle {
    Error(_) ->
      response.xrpc_error(400, "InvalidRequest", "Missing handle parameter")
    Ok(handle_val) -> {
      let result =
        sqlight.query(
          "SELECT did FROM accounts WHERE handle = ? LIMIT 1",
          ctx.db,
          [sqlight.text(handle_val)],
          decode.at([0], decode.string),
        )

      case result {
        Ok([user_did]) ->
          response.json_response(
            200,
            json.object([#("did", json.string(user_did))]),
          )
        _ ->
          response.xrpc_error(
            400,
            "HandleNotFound",
            "Handle not found: " <> handle_val,
          )
      }
    }
  }
}

// ---------------------------------------------------------------------------
// resolveDid — DID -> DID document
// ---------------------------------------------------------------------------

pub fn resolve_did(req: Request, ctx: Context) -> Response {
  case list.key_find(wisp.get_query(req), "did") {
    Error(_) ->
      response.xrpc_error(400, "InvalidRequest", "Missing did parameter")
    Ok(did) ->
      case fetch_did_document(did, ctx) {
        Ok(doc_json) ->
          // doc_json is already a JSON object string; wrap as { didDoc: ... }
          raw_json_response(200, "{\"didDoc\":" <> doc_json <> "}")
        Error(msg) -> response.xrpc_error(404, "DidNotFound", msg)
      }
  }
}

// ---------------------------------------------------------------------------
// resolveIdentity — handle or DID -> full identity info
// ---------------------------------------------------------------------------

pub fn resolve_identity(req: Request, ctx: Context) -> Response {
  case list.key_find(wisp.get_query(req), "identifier") {
    Error(_) ->
      response.xrpc_error(400, "InvalidRequest", "Missing identifier parameter")
    Ok(identifier) -> {
      let did_result = case string.starts_with(identifier, "did:") {
        True -> Ok(identifier)
        False ->
          resolve_handle_to_did(identifier, ctx)
          |> result.replace_error("Unable to resolve handle: " <> identifier)
      }

      case did_result {
        Error(msg) -> response.xrpc_error(400, "HandleNotFound", msg)
        Ok(did) ->
          case fetch_did_document(did, ctx) {
            Ok(doc_json) -> {
              let handle = lookup_handle_for_did(did, ctx)
              let body =
                "{\"did\":"
                <> json.to_string(json.string(did))
                <> ",\"handle\":"
                <> json.to_string(json.string(handle))
                <> ",\"didDoc\":"
                <> doc_json
                <> "}"
              raw_json_response(200, body)
            }
            Error(msg) -> response.xrpc_error(404, "DidNotFound", msg)
          }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// updateHandle — auth required; change the current account's handle
// ---------------------------------------------------------------------------

pub fn update_handle(req: Request, ctx: Context) -> Response {
  case server.get_auth_did_full(req, ctx) {
    Error(resp) -> resp
    Ok(user_did) -> {
      use body <- wisp.require_json(req)
      let decoder = {
        use handle <- decode.field("handle", decode.string)
        decode.success(handle)
      }
      case decode.run(body, decoder) {
        Error(_) ->
          response.xrpc_error(400, "InvalidRequest", "Missing handle")
        Ok(handle) -> {
          let full_handle = case string.contains(handle, ".") {
            True -> handle
            False -> handle <> "." <> ctx.config.handle_domain
          }

          // Verify the new handle isn't already taken by a different account
          let taken =
            sqlight.query(
              "SELECT did FROM accounts WHERE handle = ? LIMIT 1",
              ctx.db,
              [sqlight.text(full_handle)],
              decode.at([0], decode.string),
            )
          case taken {
            Ok([existing_did]) if existing_did != user_did ->
              response.xrpc_error(
                400,
                "HandleNotAvailable",
                "Handle already taken: " <> full_handle,
              )
            _ -> {
              // Update the local account handle
              let update_result =
                sqlight.query(
                  "UPDATE accounts SET handle = ? WHERE did = ? RETURNING did",
                  ctx.db,
                  [sqlight.text(full_handle), sqlight.text(user_did)],
                  decode.at([0], decode.string),
                )
              case update_result {
                Error(_) ->
                  response.xrpc_error(
                    500,
                    "InternalError",
                    "Failed to update handle",
                  )
                Ok(_) -> {
                  // For did:plc accounts, submit a PLC operation updating
                  // alsoKnownAs. Failures here are logged via the returned
                  // error but do not roll back the local change.
                  let _ = case string.starts_with(user_did, "did:plc:") {
                    True -> submit_handle_plc_update(user_did, full_handle, ctx)
                    False -> Ok(Nil)
                  }

                  // Emit a #identity firehose event so relays re-resolve the
                  // handle for this DID.
                  process.send(
                    ctx.firehose,
                    firehose.Emit(firehose.IdentityEvent(user_did, full_handle)),
                  )
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

fn submit_handle_plc_update(
  did: String,
  full_handle: String,
  ctx: Context,
) -> Result(Nil, String) {
  use #(private_key, public_key) <- result.try(get_repo_keys(did, ctx))
  use #(prev_cid, current_rotation_keys) <- result.try(plc.fetch_last_op(did))
  let op_json =
    plc.create_update_operation(
      private_key,
      public_key,
      ctx.config.rotation_key,
      current_rotation_keys,
      full_handle,
      ctx.config.public_url,
      prev_cid,
    )
  plc.submit_operation(did, op_json)
}

// ---------------------------------------------------------------------------
// getRecommendedDidCredentials — auth required
// ---------------------------------------------------------------------------

pub fn get_recommended_did_credentials(req: Request, ctx: Context) -> Response {
  case server.get_auth_did(req, ctx) {
    Error(resp) -> resp
    Ok(user_did) -> {
      let handle = lookup_handle_for_did(user_did, ctx)
      case get_repo_keys(user_did, ctx) {
        Error(_) ->
          response.xrpc_error(500, "InternalError", "No signing key found")
        Ok(#(_priv, public_key)) -> {
          let did_key = public_key_to_did_key(public_key)
          let rotation_keys = case ctx.config.rotation_key {
            Some(rot_priv) -> [plc.rotation_did_key(rot_priv)]
            None -> [did_key]
          }
          response.json_response(
            200,
            json.object([
              #("rotationKeys", json.array(rotation_keys, json.string)),
              #(
                "verificationMethods",
                json.object([#("atproto", json.string(did_key))]),
              ),
              #(
                "alsoKnownAs",
                json.array(["at://" <> handle], json.string),
              ),
              #(
                "services",
                json.object([
                  #(
                    "atproto_pds",
                    json.object([
                      #(
                        "type",
                        json.string("AtprotoPersonalDataServer"),
                      ),
                      #("endpoint", json.string(ctx.config.public_url)),
                    ]),
                  ),
                ]),
              ),
            ]),
          )
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// signPlcOperation — auth required; sign a (handle-updating) PLC operation
// ---------------------------------------------------------------------------

pub fn sign_plc_operation(req: Request, ctx: Context) -> Response {
  case server.get_auth_did_full(req, ctx) {
    Error(resp) -> resp
    Ok(user_did) -> {
      use body <- wisp.require_json(req)
      // Optional alsoKnownAs list; default to the account's current handle.
      let decoder = {
        use aka <- decode.optional_field(
          "alsoKnownAs",
          None,
          decode.optional(decode.list(decode.string)),
        )
        decode.success(aka)
      }
      let aka = case decode.run(body, decoder) {
        Ok(Some(list)) -> list
        _ -> []
      }
      let handle = case aka {
        [first, ..] -> strip_at_prefix(first)
        [] -> lookup_handle_for_did(user_did, ctx)
      }

      case string.starts_with(user_did, "did:plc:"), get_repo_keys(user_did, ctx) {
        True, Ok(#(private_key, public_key)) -> {
          let #(prev, current_rotation_keys) = case
            plc.fetch_last_op(user_did)
          {
            Ok(last_op) -> last_op
            Error(_) -> #("", [])
          }
          let op_json =
            plc.create_update_operation(
              private_key,
              public_key,
              ctx.config.rotation_key,
              current_rotation_keys,
              handle,
              ctx.config.public_url,
              prev,
            )
          // The signed operation is itself a JSON object; return it under
          // "operation" as the lexicon specifies.
          raw_json_response(200, "{\"operation\":" <> op_json <> "}")
        }
        False, _ ->
          response.xrpc_error(
            400,
            "InvalidRequest",
            "signPlcOperation is only supported for did:plc accounts",
          )
        _, _ ->
          response.xrpc_error(500, "InternalError", "No signing key found")
      }
    }
  }
}

// ---------------------------------------------------------------------------
// submitPlcOperation — auth required; POST a signed op to plc.directory
// ---------------------------------------------------------------------------

pub fn submit_plc_operation(req: Request, ctx: Context) -> Response {
  case server.get_auth_did_full(req, ctx) {
    Error(resp) -> resp
    Ok(user_did) -> {
      use body <- wisp.require_json(req)
      // The "operation" field is an arbitrary signed op object; re-serialize it.
      let decoder = {
        use op <- decode.field("operation", decode.dynamic)
        decode.success(op)
      }
      case decode.run(body, decoder) {
        Error(_) ->
          response.xrpc_error(400, "InvalidRequest", "Missing operation")
        Ok(op_dyn) -> {
          let op_json = dynamic_to_json_string(op_dyn)
          case plc.submit_operation(user_did, op_json) {
            Ok(_) -> wisp.ok()
            Error(msg) -> response.xrpc_error(400, "InvalidRequest", msg)
          }
        }
      }
    }
  }
}

@external(erlang, "gleam_pds_repo_ffi", "extract_record_json")
fn dynamic_to_json_string(body: dynamic.Dynamic) -> String

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn raw_json_response(status: Int, body: String) -> Response {
  wisp.response(status)
  |> wisp.set_header("content-type", "application/json")
  |> wisp.set_body(wisp.Text(body))
}

fn strip_at_prefix(aka: String) -> String {
  case string.starts_with(aka, "at://") {
    True -> string.drop_start(aka, 5)
    False -> aka
  }
}

fn get_repo_keys(
  did: String,
  ctx: Context,
) -> Result(#(BitArray, BitArray), String) {
  let key_decoder = {
    use priv <- decode.field(0, decode.bit_array)
    use public <- decode.field(1, decode.bit_array)
    decode.success(#(priv, public))
  }
  let result =
    sqlight.query(
      "SELECT signing_key_private, signing_key_public FROM repos WHERE did = ? LIMIT 1",
      ctx.db,
      [sqlight.text(did)],
      key_decoder,
    )
  case result {
    Ok([keys]) -> Ok(keys)
    _ -> Error("No signing key found for " <> did)
  }
}

fn lookup_handle_for_did(did: String, ctx: Context) -> String {
  let result =
    sqlight.query(
      "SELECT handle FROM accounts WHERE did = ? LIMIT 1",
      ctx.db,
      [sqlight.text(did)],
      decode.at([0], decode.string),
    )
  case result {
    Ok([handle]) -> handle
    _ -> "handle.invalid"
  }
}

/// Resolve a handle to a DID: first check the local account table, then fall
/// back to the well-known HTTPS method (GET https://{handle}/.well-known/atproto-did).
fn resolve_handle_to_did(handle: String, ctx: Context) -> Result(String, Nil) {
  let local =
    sqlight.query(
      "SELECT did FROM accounts WHERE handle = ? LIMIT 1",
      ctx.db,
      [sqlight.text(handle)],
      decode.at([0], decode.string),
    )
  case local {
    Ok([did]) -> Ok(did)
    _ -> resolve_handle_well_known(handle)
  }
}

fn resolve_handle_well_known(handle: String) -> Result(String, Nil) {
  let url = "https://" <> handle <> "/.well-known/atproto-did"
  case request.to(url) {
    Error(_) -> Error(Nil)
    Ok(req0) -> {
      let req = request.set_method(req0, http.Get)
      case httpc.send(req) {
        Ok(resp) ->
          case resp.status {
            200 -> {
              let did = string.trim(resp.body)
              case string.starts_with(did, "did:") {
                True -> Ok(did)
                False -> Error(Nil)
              }
            }
            _ -> Error(Nil)
          }
        Error(_) -> Error(Nil)
      }
    }
  }
}

/// Fetch a DID document (as a raw JSON string) for a did:plc or did:web.
fn fetch_did_document(did: String, ctx: Context) -> Result(String, String) {
  case string.starts_with(did, "did:plc:") {
    True -> http_get_body("https://plc.directory/" <> did)
    False ->
      case string.starts_with(did, "did:web:") {
        True -> fetch_web_did_document(did, ctx)
        False -> Error("Unsupported DID method: " <> did)
      }
  }
}

fn fetch_web_did_document(did: String, ctx: Context) -> Result(String, String) {
  // If it's our own hostname, serve locally.
  let own_did = "did:web:" <> string.replace(ctx.config.hostname, ":", "%3A")
  case did == own_did {
    True ->
      Ok(json.to_string(did_module.server_did_document(
        ctx.config.hostname,
        ctx.config.public_url,
      )))
    False -> {
      // did:web:host or did:web:host:path:segments
      let rest = string.drop_start(did, 8)
      let url = case string.split(rest, ":") {
        [host] -> {
          let host = string.replace(host, "%3A", ":")
          "https://" <> host <> "/.well-known/did.json"
        }
        [host, ..segments] -> {
          let host = string.replace(host, "%3A", ":")
          "https://" <> host <> "/" <> string.join(segments, "/") <> "/did.json"
        }
        [] -> ""
      }
      case url {
        "" -> Error("Invalid did:web: " <> did)
        u -> http_get_body(u)
      }
    }
  }
}

fn http_get_body(url: String) -> Result(String, String) {
  case request.to(url) {
    Error(_) -> Error("Invalid URL: " <> url)
    Ok(req0) -> {
      let req = request.set_method(req0, http.Get)
      case httpc.send(req) {
        Ok(resp) ->
          case resp.status {
            200 -> Ok(resp.body)
            s -> Error("DID document fetch failed: " <> int.to_string(s))
          }
        Error(_) -> Error("Failed to fetch DID document")
      }
    }
  }
}
