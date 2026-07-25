/// Proxy XRPC requests to the Bluesky appview with service auth

import gleam_pds/context.{type Context}
import gleam_pds/crypto
import gleam_pds/web/response
import gleam_pds/xrpc/server
import gleam/bit_array
import gleam/dynamic
import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/http/response as http_response
import gleam/httpc
import gleam/json
import gleam/list
import gleam/result
import gleam/string
import sqlight
import wisp.{type Request, type Response}

const appview_url = "https://api.bsky.app"

const appview_did = "did:web:api.bsky.app"

const chat_url = "https://api.bsky.chat"

const chat_did = "did:web:api.bsky.chat"

fn service_for_method(method: String) -> #(String, String) {
  case string.starts_with(method, "chat.bsky.") {
    True -> #(chat_url, chat_did)
    False -> #(appview_url, appview_did)
  }
}

/// Create a service auth JWT signed with the user's repo signing key (ES256)
fn create_service_jwt(
  user_did: String,
  aud: String,
  lxm: String,
  ctx: Context,
) -> Result(String, String) {
  let key_result =
    sqlight.query(
      "SELECT signing_key_private FROM repos WHERE did = ? LIMIT 1",
      ctx.db,
      [sqlight.text(user_did)],
      decode.at([0], decode.bit_array),
    )
  case key_result {
    Ok([private_key]) -> {
      let now = crypto.timestamp_microseconds() / 1_000_000
      let exp = now + 60
      let jti = crypto.random_string(16)

      let header =
        json.to_string(json.object([
          #("typ", json.string("JWT")),
          #("alg", json.string("ES256")),
        ]))

      let payload =
        json.to_string(json.object([
          #("iss", json.string(user_did)),
          #("aud", json.string(aud)),
          #("lxm", json.string(lxm)),
          #("iat", json.int(now)),
          #("exp", json.int(exp)),
          #("jti", json.string(jti)),
        ]))

      let header_b64 = crypto.base64url_encode(bit_array.from_string(header))
      let payload_b64 = crypto.base64url_encode(bit_array.from_string(payload))
      let signing_input = header_b64 <> "." <> payload_b64

      let der_sig =
        crypto.sign_es256(
          bit_array.from_string(signing_input),
          private_key,
        )
      let raw_sig = der_to_raw(der_sig)
      let sig_b64 = crypto.base64url_encode(raw_sig)

      Ok(signing_input <> "." <> sig_b64)
    }
    _ -> Error("No signing key found for " <> user_did)
  }
}

@external(erlang, "gleam_pds_plc_ffi", "der_to_raw_es256")
fn der_to_raw(der_sig: BitArray) -> BitArray

/// Proxy a GET XRPC to the appview
pub fn proxy_get(
  req: Request,
  ctx: Context,
  method: String,
) -> Response {
  let #(base_url, aud) = service_for_method(method)
  let query_string =
    wisp.get_query(req)
    |> list.map(fn(pair) { pair.0 <> "=" <> pair.1 })
    |> string.join("&")

  let url =
    base_url
    <> "/xrpc/"
    <> method
    <> case query_string {
      "" -> ""
      qs -> "?" <> qs
    }

  case request.to(url) {
    Error(_) -> wisp.internal_server_error()
    Ok(proxy_req) -> {
      let proxy_req =
        proxy_req
        |> request.set_method(http.Get)
        |> add_service_auth(req, ctx, method, aud)
        |> forward_headers(req)

      case httpc.send(proxy_req) {
        Ok(resp) -> forward_response(resp)
        Error(_) -> wisp.internal_server_error()
      }
    }
  }
}

/// Proxy a POST XRPC to the appview
pub fn proxy_post(
  req: Request,
  ctx: Context,
  method: String,
) -> Response {
  let #(base_url, aud) = service_for_method(method)
  let url = base_url <> "/xrpc/" <> method

  use body <- wisp.require_json(req)
  let body_str = encode_dynamic_raw(body)

  case request.to(url) {
    Error(_) -> wisp.internal_server_error()
    Ok(proxy_req) -> {
      let proxy_req =
        proxy_req
        |> request.set_method(http.Post)
        |> request.set_header("content-type", "application/json")
        |> request.set_body(body_str)
        |> add_service_auth(req, ctx, method, aud)

      case httpc.send(proxy_req) {
        Ok(resp) -> forward_response(resp)
        Error(_) -> wisp.internal_server_error()
      }
    }
  }
}

/// Add service auth JWT to proxy request if user is authenticated
fn add_service_auth(
  proxy_req: request.Request(String),
  original: Request,
  ctx: Context,
  method: String,
  aud: String,
) -> request.Request(String) {
  case server.get_auth_did(original, ctx) {
    Ok(did) -> {
      case create_service_jwt(did, aud, method, ctx) {
        Ok(jwt) ->
          request.set_header(proxy_req, "authorization", "Bearer " <> jwt)
        Error(_) -> proxy_req
      }
    }
    Error(_) -> proxy_req
  }
}

/// Forward relevant headers from original request
fn forward_headers(
  proxy_req: request.Request(String),
  original: Request,
) -> request.Request(String) {
  let proxy_req = case list.key_find(original.headers, "accept-language") {
    Ok(v) -> request.set_header(proxy_req, "accept-language", v)
    Error(_) -> proxy_req
  }
  case list.key_find(original.headers, "atproto-accept-labelers") {
    Ok(v) -> request.set_header(proxy_req, "atproto-accept-labelers", v)
    Error(_) -> proxy_req
  }
}

/// Forward upstream response back to client
fn forward_response(resp: http_response.Response(String)) -> Response {
  let content_type =
    http_response.get_header(resp, "content-type")
    |> result.unwrap("application/json")
  wisp.response(resp.status)
  |> wisp.set_header("content-type", content_type)
  |> wisp.set_body(wisp.Text(resp.body))
}

@external(erlang, "gleam_pds_repo_ffi", "extract_record_json")
fn encode_dynamic_raw(body: dynamic.Dynamic) -> String

// --- Local handlers for preferences (stored on PDS, not proxied) ---

pub fn get_preferences(req: Request, ctx: Context) -> Response {
  case server.get_auth_did(req, ctx) {
    Error(resp) -> resp
    Ok(user_did) -> {
      let result =
        sqlight.query(
          "SELECT preferences FROM actor_preferences WHERE did = ? LIMIT 1",
          ctx.db,
          [sqlight.text(user_did)],
          decode.at([0], decode.string),
        )
      case result {
        Ok([prefs_json]) ->
          wisp.response(200)
          |> wisp.set_header("content-type", "application/json")
          |> wisp.set_body(wisp.Text(prefs_json))
        _ ->
          response.json_response(
            200,
            json.object([
              #("preferences", json.preprocessed_array([])),
            ]),
          )
      }
    }
  }
}

pub fn put_preferences(req: Request, ctx: Context) -> Response {
  case server.get_auth_did(req, ctx) {
    Error(resp) -> resp
    Ok(user_did) -> {
      use body <- wisp.require_json(req)
      let prefs_str = encode_dynamic_raw(body)
      let _ =
        sqlight.query(
          "INSERT INTO actor_preferences (did, preferences) VALUES (?, ?)
           ON CONFLICT(did) DO UPDATE SET preferences = ?",
          ctx.db,
          [
            sqlight.text(user_did),
            sqlight.text(prefs_str),
            sqlight.text(prefs_str),
          ],
          decode.at([0], decode.string),
        )
      wisp.ok()
    }
  }
}
