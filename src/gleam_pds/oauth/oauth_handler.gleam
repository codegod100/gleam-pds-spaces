/// OAuth 2.0 Authorization Server for AT Protocol
/// Supports PKCE, DPoP, and passkey authentication

import gleam_pds/context.{type Context}
import gleam_pds/oauth/client_metadata
import gleam_pds/web/pages
import gleam_pds/crypto
import gleam_pds/web/response
import gleam/bit_array
import gleam/dynamic/decode
import gleam/http.{Get, Post}
import gleam/json
import gleam/list
import gleam/option.{Some}
import gleam/result
import gleam/string
import sqlight
import wisp.{type Request, type Response}

/// OAuth Authorization Server Metadata
pub fn metadata(_req: Request, ctx: Context) -> Response {
  let base = ctx.config.public_url
  response.json_response(
    200,
    json.object([
      #("issuer", json.string(base)),
      #("authorization_endpoint", json.string(base <> "/oauth/authorize")),
      #("token_endpoint", json.string(base <> "/oauth/token")),
      #(
        "pushed_authorization_request_endpoint",
        json.string(base <> "/oauth/par"),
      ),
      #("jwks_uri", json.string(base <> "/oauth/jwks")),
      #(
        "scopes_supported",
        json.array(
          ["atproto", "transition:generic", "transition:chat.bsky"],
          json.string,
        ),
      ),
      #("response_types_supported", json.array(["code"], json.string)),
      #(
        "grant_types_supported",
        json.array(
          ["authorization_code", "refresh_token"],
          json.string,
        ),
      ),
      #(
        "code_challenge_methods_supported",
        json.array(["S256"], json.string),
      ),
      #(
        "token_endpoint_auth_methods_supported",
        json.array(["none", "private_key_jwt"], json.string),
      ),
      #(
        "token_endpoint_auth_signing_alg_values_supported",
        json.array(["ES256"], json.string),
      ),
      #(
        "dpop_signing_alg_values_supported",
        json.array(["ES256"], json.string),
      ),
      #("require_pushed_authorization_requests", json.bool(True)),
      #("subject_types_supported", json.array(["public"], json.string)),
      #("client_id_metadata_document_supported", json.bool(True)),
    ]),
  )
}

/// OAuth Protected Resource Metadata (RFC 9728)
pub fn protected_resource(_req: Request, ctx: Context) -> Response {
  let base = ctx.config.public_url
  response.json_response(
    200,
    json.object([
      #("resource", json.string(base)),
      #(
        "authorization_servers",
        json.array([base], json.string),
      ),
      #(
        "scopes_supported",
        json.array(
          ["atproto", "transition:generic", "transition:chat.bsky"],
          json.string,
        ),
      ),
      #(
        "bearer_methods_supported",
        json.array(["header"], json.string),
      ),
      #(
        "resource_documentation",
        json.string("https://atproto.com"),
      ),
    ]),
  )
}

/// JWKS endpoint.
///
/// S2: never publish the symmetric HS256 signing key here. Access tokens are
/// signed with an internal HMAC secret that resource servers must not (and
/// cannot) use to verify tokens, and exposing it as an `oct` JWK would leak the
/// forging key. We therefore publish an empty key set.
pub fn jwks(_req: Request, _ctx: Context) -> Response {
  response.json_response(
    200,
    json.object([#("keys", json.preprocessed_array([]))]),
  )
}

/// Pushed Authorization Request
pub fn par(req: Request, ctx: Context) -> Response {
  case req.method {
    Post -> {
      use formdata <- wisp.require_form(req)
      let vals = formdata.values
      let client_id = list.key_find(vals, "client_id")
      let redirect_uri = list.key_find(vals, "redirect_uri")
      let code_challenge = list.key_find(vals, "code_challenge")
      let scope =
        list.key_find(vals, "scope") |> result.unwrap("atproto")

      case client_id, redirect_uri, code_challenge {
        Ok(cid), Ok(ruri), Ok(cc) -> {
          // Fetch the client-id-metadata-document and refuse requests whose
          // redirect_uri/grants/scope the client never declared.
          case client_metadata.validate(cid, ruri, scope) {
            Error(why) ->
              response.xrpc_error(400, "invalid_client_metadata", why)
            Ok(Nil) -> par_store_request(vals, cid, ruri, cc, ctx)
          }
        }
        _, _, _ ->
          response.xrpc_error(
            400,
            "invalid_request",
            "Missing required parameters",
          )
      }
    }
    _ -> wisp.method_not_allowed([Post])
  }
}

fn par_store_request(
  vals: List(#(String, String)),
  cid: String,
  ruri: String,
  cc: String,
  ctx: Context,
) -> Response {
  let code_challenge_method =
    list.key_find(vals, "code_challenge_method")
    |> result.unwrap("S256")
  let scope = list.key_find(vals, "scope") |> result.unwrap("atproto")
  let state = list.key_find(vals, "state") |> result.unwrap("")
  // atproto clients send the handle the user typed as login_hint; keep it
  // so the authorize form can prefill the identifier field.
  let login_hint = list.key_find(vals, "login_hint") |> result.unwrap("")
  let id = crypto.random_string(32)
  let request_uri = "urn:ietf:params:oauth:request_uri:" <> id

  let _ =
    sqlight.query(
      "INSERT INTO oauth_auth_requests (id, client_id, redirect_uri, code_challenge, code_challenge_method, scope, state, login_hint, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '+10 minutes'))",
      ctx.db,
      [
        sqlight.text(id),
        sqlight.text(cid),
        sqlight.text(ruri),
        sqlight.text(cc),
        sqlight.text(code_challenge_method),
        sqlight.text(scope),
        sqlight.text(state),
        sqlight.text(login_hint),
      ],
      decode.at([0], decode.string),
    )

  response.json_response(
    201,
    json.object([
      #("request_uri", json.string(request_uri)),
      #("expires_in", json.int(600)),
    ]),
  )
  // Hand the client its first DPoP nonce here so the token request doesn't
  // need a use_dpop_nonce retry round-trip.
  |> wisp.set_header("dpop-nonce", crypto.dpop_nonce(ctx.config.secret_key))
}

/// Authorization endpoint
pub fn authorize(req: Request, ctx: Context) -> Response {
  case req.method {
    Get -> {
      let query = wisp.get_query(req)
      let request_uri =
        list.key_find(query, "request_uri")
        |> result.unwrap("")
      let id =
        string.replace(
          request_uri,
          "urn:ietf:params:oauth:request_uri:",
          "",
        )
      let query_hint =
        list.key_find(query, "login_hint") |> result.unwrap("")
      authorize_page(id, query_hint, ctx)
    }
    Post -> {
      use formdata <- wisp.require_form(req)
      let vals = formdata.values
      let request_id = list.key_find(vals, "request_id") |> result.unwrap("")
      let identifier = list.key_find(vals, "identifier")
      let password = list.key_find(vals, "password")

      case identifier, password {
        Ok(ident), Ok(pw) -> {
          let account_result =
            sqlight.query(
              "SELECT did, password_hash FROM accounts WHERE handle = ? OR email = ? LIMIT 1",
              ctx.db,
              [sqlight.text(ident), sqlight.text(ident)],
              {
                use d <- decode.field(0, decode.string)
                use p <- decode.field(1, decode.optional(decode.string))
                decode.success(#(d, p))
              },
            )

          case account_result {
            Ok([#(user_did, Some(pw_hash))]) -> {
              case crypto.verify_password(pw, pw_hash) {
                True -> complete_authorization(request_id, user_did, ctx)
                False -> authorize_page(request_id, "", ctx)
              }
            }
            _ -> authorize_page(request_id, "", ctx)
          }
        }
        _, _ -> response.xrpc_error(400, "invalid_request", "Missing fields")
      }
    }
    _ -> wisp.method_not_allowed([Get, Post])
  }
}

fn authorize_page(
  request_id: String,
  fallback_hint: String,
  ctx: Context,
) -> Response {
  // Prefer the login_hint stored with the pushed request; fall back to a
  // direct query param. pages.oauth_authorize_page escapes it.
  let stored_hint =
    sqlight.query(
      "SELECT login_hint FROM oauth_auth_requests WHERE id = ? LIMIT 1",
      ctx.db,
      [sqlight.text(request_id)],
      decode.at([0], decode.optional(decode.string)),
    )
  let hint = case stored_hint {
    Ok([Some(h)]) if h != "" -> h
    _ -> fallback_hint
  }
  pages.oauth_authorize_page(request_id, hint, ctx)
}

pub fn complete_authorization(
  request_id: String,
  user_did: String,
  ctx: Context,
) -> Response {
  let code = crypto.random_string(32)
  let _ =
    sqlight.query(
      "UPDATE oauth_auth_requests SET did = ?, code = ? WHERE id = ?",
      ctx.db,
      [
        sqlight.text(user_did),
        sqlight.text(code),
        sqlight.text(request_id),
      ],
      decode.at([0], decode.string),
    )

  let auth_req =
    sqlight.query(
      "SELECT redirect_uri, state FROM oauth_auth_requests WHERE id = ? LIMIT 1",
      ctx.db,
      [sqlight.text(request_id)],
      {
        use r <- decode.field(0, decode.string)
        use s <- decode.field(1, decode.string)
        decode.success(#(r, s))
      },
    )

  case auth_req {
    Ok([#(redirect_uri, state)]) -> {
      let sep = case string.contains(redirect_uri, "?") {
        True -> "&"
        False -> "?"
      }
      let redirect =
        redirect_uri
        <> sep
        <> "code="
        <> code
        <> "&state="
        <> state
        <> "&iss="
        <> ctx.config.public_url
      wisp.redirect(redirect)
    }
    _ ->
      response.json_response(
        200,
        json.object([#("code", json.string(code))]),
      )
  }
}

/// Token endpoint
pub fn token(req: Request, ctx: Context) -> Response {
  case req.method {
    Post -> {
      // C6: DPoP is advertised, so every token request must carry a valid DPoP
      // proof. The proof's key thumbprint is bound into the issued tokens.
      let resp = case require_dpop_proof(req, ctx) {
        Error(resp) -> resp
        Ok(jkt) -> {
          use formdata <- wisp.require_form(req)
          let vals = formdata.values
          let grant_type = list.key_find(vals, "grant_type")

          case grant_type {
            Ok("authorization_code") -> handle_auth_code(vals, jkt, ctx)
            Ok("refresh_token") -> handle_refresh(vals, jkt, ctx)
            _ ->
              response.xrpc_error(
                400,
                "unsupported_grant_type",
                "Unsupported grant type",
              )
          }
        }
      }
      // RFC 9449 §8: always tell the client the nonce to use next, on
      // successes and failures alike.
      wisp.set_header(
        resp,
        "dpop-nonce",
        crypto.dpop_nonce(ctx.config.secret_key),
      )
    }
    _ -> wisp.method_not_allowed([Post])
  }
}

/// Validate the DPoP proof presented at the token endpoint and return its JWK
/// thumbprint (the value bound into `cnf.jkt`).
fn require_dpop_proof(req: Request, ctx: Context) -> Result(String, Response) {
  case list.key_find(req.headers, "dpop") {
    Error(_) ->
      Error(response.xrpc_error(
        400,
        "invalid_dpop_proof",
        "Missing required DPoP proof",
      ))
    Ok(proof) -> {
      let htu = ctx.config.public_url <> req.path
      let nonces = crypto.dpop_nonces_accepted(ctx.config.secret_key)
      case crypto.verify_dpop(proof, "POST", htu, option.None, nonces) {
        Ok(jkt) -> Ok(jkt)
        // The caller adds the DPoP-Nonce header to every token response, so
        // the client has a fresh nonce to retry this error with.
        Error(crypto.DpopBadNonce) ->
          Error(response.xrpc_error(
            400,
            "use_dpop_nonce",
            "Authorization server requires nonce in DPoP proof",
          ))
        Error(_) ->
          Error(response.xrpc_error(
            400,
            "invalid_dpop_proof",
            "Invalid DPoP proof",
          ))
      }
    }
  }
}

fn handle_auth_code(
  params: List(#(String, String)),
  jkt: String,
  ctx: Context,
) -> Response {
  let code = list.key_find(params, "code")
  let code_verifier = list.key_find(params, "code_verifier")
  let request_client_id = list.key_find(params, "client_id")
  let request_redirect_uri = list.key_find(params, "redirect_uri")

  case code, code_verifier, request_client_id, request_redirect_uri {
    Ok(code_val), Ok(verifier), Ok(req_client_id), Ok(req_redirect_uri) -> {
      let auth_req =
        sqlight.query(
          "SELECT id, did, client_id, code_challenge, code_challenge_method, redirect_uri, scope FROM oauth_auth_requests WHERE code = ? AND expires_at > datetime('now') LIMIT 1",
          ctx.db,
          [sqlight.text(code_val)],
          {
            use id <- decode.field(0, decode.string)
            use d <- decode.field(1, decode.optional(decode.string))
            use c <- decode.field(2, decode.string)
            use cc <- decode.field(3, decode.string)
            use ccm <- decode.field(4, decode.string)
            use ruri <- decode.field(5, decode.string)
            use s <- decode.field(6, decode.string)
            decode.success(#(id, d, c, cc, ccm, ruri, s))
          },
        )

      case auth_req {
        Ok([
          #(id, Some(user_did), client_id, code_challenge, ccm, redirect_uri, scope),
        ]) -> {
          // C7: make the code strictly single-use — delete it before doing any
          // further validation so a failed exchange cannot be retried.
          let _ =
            sqlight.query(
              "DELETE FROM oauth_auth_requests WHERE id = ?",
              ctx.db,
              [sqlight.text(id)],
              decode.at([0], decode.string),
            )

          case req_client_id == client_id {
            False ->
              response.xrpc_error(
                400,
                "invalid_client",
                "client_id does not match authorization request",
              )
            True ->
              // C7: redirect_uri must match the one used at authorization
              // (RFC 6749 4.1.3).
              case req_redirect_uri == redirect_uri {
                False ->
                  response.xrpc_error(
                    400,
                    "invalid_grant",
                    "redirect_uri does not match authorization request",
                  )
                True ->
                  // C7: only S256 PKCE is permitted; reject "plain".
                  case ccm == "S256" {
                    False ->
                      response.xrpc_error(
                        400,
                        "invalid_grant",
                        "Unsupported code_challenge_method",
                      )
                    True -> {
                      // Verify PKCE: S256 = BASE64URL(SHA256(verifier)),
                      // compared in constant time.
                      let computed =
                        crypto.base64url_encode(
                          crypto.sha256(bit_array.from_string(verifier)),
                        )
                      case
                        crypto.secure_compare(
                          bit_array.from_string(computed),
                          bit_array.from_string(code_challenge),
                        )
                      {
                        True -> issue_tokens(user_did, client_id, scope, jkt, ctx)
                        False ->
                          response.xrpc_error(
                            400,
                            "invalid_grant",
                            "Invalid code verifier",
                          )
                      }
                    }
                  }
              }
          }
        }
        _ ->
          response.xrpc_error(
            400,
            "invalid_grant",
            "Invalid or expired code",
          )
      }
    }
    _, _, _, _ ->
      response.xrpc_error(
        400,
        "invalid_request",
        "Missing code, code_verifier, client_id, or redirect_uri",
      )
  }
}

fn handle_refresh(
  params: List(#(String, String)),
  jkt: String,
  ctx: Context,
) -> Response {
  case list.key_find(params, "refresh_token"), list.key_find(params, "client_id") {
    Ok(rt), Ok(req_client_id) -> {
      // S5: a NULL refresh_expires_at must NOT be treated as immortal.
      let result =
        sqlight.query(
          "SELECT did, client_id, scope FROM oauth_tokens WHERE refresh_token = ? AND refresh_expires_at IS NOT NULL AND refresh_expires_at > datetime('now') LIMIT 1",
          ctx.db,
          [sqlight.text(rt)],
          {
            use d <- decode.field(0, decode.string)
            use c <- decode.field(1, decode.string)
            use s <- decode.field(2, decode.string)
            decode.success(#(d, c, s))
          },
        )

      case result {
        Ok([#(user_did, client_id, scope)]) -> {
          case req_client_id == client_id {
            False ->
              response.xrpc_error(
                400,
                "invalid_client",
                "client_id does not match refresh token",
              )
            True -> {
              let _ =
                sqlight.query(
                  "DELETE FROM oauth_tokens WHERE refresh_token = ?",
                  ctx.db,
                  [sqlight.text(rt)],
                  decode.at([0], decode.string),
                )
              issue_tokens(user_did, client_id, scope, jkt, ctx)
            }
          }
        }
        _ ->
          response.xrpc_error(
            400,
            "invalid_grant",
            "Invalid or expired refresh token",
          )
      }
    }
    _, _ ->
      response.xrpc_error(
        400,
        "invalid_request",
        "Missing refresh_token or client_id",
      )
  }
}

fn issue_tokens(
  user_did: String,
  client_id: String,
  scope: String,
  jkt: String,
  ctx: Context,
) -> Response {
  let now_ts = crypto.timestamp_microseconds() / 1_000_000
  let expires_ts = now_ts + 3600

  // Create a JWT access token so clients can extract the DID. The token is
  // DPoP-bound via cnf.jkt (C6).
  let access_token =
    crypto.create_jwt(
      [
        #("scope", json.string(scope)),
        #("sub", json.string(user_did)),
        #("iss", json.string(ctx.config.public_url)),
        #("aud", json.string("did:web:" <> string.replace(ctx.config.hostname, ":", "%3A"))),
        #("client_id", json.string(client_id)),
        #("cnf", json.object([#("jkt", json.string(jkt))])),
        #("iat", json.int(now_ts)),
        #("exp", json.int(expires_ts)),
      ],
      ctx.config.secret_key,
    )
  let refresh_token = crypto.random_string(48)

  let _ =
    sqlight.query(
      "INSERT INTO oauth_tokens (access_token, did, client_id, scope, expires_at, refresh_token, refresh_expires_at) VALUES (?, ?, ?, ?, datetime('now', '+1 hour'), ?, datetime('now', '+90 days'))",
      ctx.db,
      [
        sqlight.text(access_token),
        sqlight.text(user_did),
        sqlight.text(client_id),
        sqlight.text(scope),
        sqlight.text(refresh_token),
      ],
      decode.at([0], decode.string),
    )

  // Look up handle for the response
  let handle =
    case
      sqlight.query(
        "SELECT handle FROM accounts WHERE did = ? LIMIT 1",
        ctx.db,
        [sqlight.text(user_did)],
        decode.at([0], decode.string),
      )
    {
      Ok([h]) -> h
      _ -> ""
    }

  response.json_response(
    200,
    json.object([
      #("access_token", json.string(access_token)),
      #("token_type", json.string("DPoP")),
      #("expires_in", json.int(3600)),
      #("refresh_token", json.string(refresh_token)),
      #("scope", json.string(scope)),
      #("sub", json.string(user_did)),
      #("handle", json.string(handle)),
    ]),
  )
}

/// Client metadata endpoint
pub fn client_metadata(_req: Request, ctx: Context) -> Response {
  let base = ctx.config.public_url
  response.json_response(
    200,
    json.object([
      #("client_id", json.string(base <> "/oauth/client-metadata.json")),
      #("client_name", json.string("Gleam AT Protocol PDS")),
      #("client_uri", json.string(base)),
      #(
        "redirect_uris",
        json.array([base <> "/oauth/callback"], json.string),
      ),
      #(
        "grant_types",
        json.array(
          ["authorization_code", "refresh_token"],
          json.string,
        ),
      ),
      #("response_types", json.array(["code"], json.string)),
      #("scope", json.string("atproto transition:generic")),
      #("token_endpoint_auth_method", json.string("none")),
      #("application_type", json.string("web")),
      #("dpop_bound_access_tokens", json.bool(True)),
    ]),
  )
}
