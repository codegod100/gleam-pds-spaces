/// WebAuthn/Passkey handler for registration and authentication

import gleam_pds/context.{type Context}
import gleam_pds/crypto
import gleam_pds/ratelimit
import gleam_pds/web/response
import gleam_pds/xrpc/server
import gleam/bit_array
import gleam/dynamic/decode
import gleam/http.{Post}
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import sqlight
import wisp.{type Request, type Response}

// -- WebAuthn FFI --

pub type AttestationResult {
  AttestationResult(
    credential_id: String,
    public_key: BitArray,
    sign_count: Int,
  )
}

@external(erlang, "gleam_pds_webauthn_ffi", "parse_attestation_object")
fn ffi_parse_attestation(
  b64_attestation: String,
) -> Result(decode.Dynamic, String)

@external(erlang, "gleam_pds_webauthn_ffi", "verify_assertion")
fn ffi_verify_assertion(
  b64_auth_data: String,
  b64_client_data: String,
  b64_signature: String,
  public_key: BitArray,
) -> Bool

@external(erlang, "gleam_pds_webauthn_ffi", "parse_authenticator_data")
fn ffi_parse_auth_data(
  b64_auth_data: String,
) -> Result(decode.Dynamic, String)

/// Parsed WebAuthn authenticatorData fields we care about.
type AuthData {
  AuthData(rp_id_hash: BitArray, sign_count: Int, user_present: Bool)
}

fn parse_auth_data(b64_auth_data: String) -> Result(AuthData, Nil) {
  case ffi_parse_auth_data(b64_auth_data) {
    Ok(dyn) -> {
      let decoder = {
        use rp_id_hash <- decode.field("rp_id_hash", decode.bit_array)
        use sign_count <- decode.field("sign_count", decode.int)
        use up <- decode.field("user_present", decode.int)
        decode.success(AuthData(
          rp_id_hash: rp_id_hash,
          sign_count: sign_count,
          user_present: up == 1,
        ))
      }
      case decode.run(dyn, decoder) {
        Ok(ad) -> Ok(ad)
        Error(_) -> Error(Nil)
      }
    }
    Error(_) -> Error(Nil)
  }
}

/// Parsed WebAuthn clientDataJSON (base64url-encoded).
type ClientData {
  ClientData(typ: String, challenge: String, origin: String)
}

fn parse_client_data(b64_client_data: String) -> Result(ClientData, Nil) {
  use bytes <- result.try(crypto.base64url_decode(b64_client_data))
  use str <- result.try(bit_array.to_string(bytes))
  let decoder = {
    use typ <- decode.field("type", decode.string)
    use challenge <- decode.field("challenge", decode.string)
    use origin <- decode.field("origin", decode.string)
    decode.success(ClientData(typ: typ, challenge: challenge, origin: origin))
  }
  case json.parse(str, decoder) {
    Ok(cd) -> Ok(cd)
    Error(_) -> Error(Nil)
  }
}

// -- Routes --

pub fn handle(
  req: Request,
  ctx: Context,
  path: List(String),
) -> Response {
  case req.method, path {
    Post, ["register", "begin"] -> register_begin(req, ctx)
    Post, ["register", "finish"] -> register_finish(req, ctx)
    // Passkey login is an unauthenticated login path, so it gets the same
    // per-IP budget as createSession.
    Post, ["login", "begin"] -> login_guard(req, ctx, fn() { login_begin(req, ctx) })
    Post, ["login", "finish"] ->
      login_guard(req, ctx, fn() { login_finish(req, ctx) })
    _, _ -> wisp.not_found()
  }
}

fn login_guard(req: Request, ctx: Context, next: fn() -> Response) -> Response {
  ratelimit.guard(
    ctx,
    ratelimit.create_session_limits(),
    ratelimit.ip_key(req),
    next,
  )
}

// -- Register --

fn register_begin(req: Request, ctx: Context) -> Response {
  case server.get_auth_did_full(req, ctx) {
    Error(resp) -> resp
    Ok(user_did) -> {
      let account_result =
        sqlight.query(
          "SELECT handle FROM accounts WHERE did = ? LIMIT 1",
          ctx.db,
          [sqlight.text(user_did)],
          decode.at([0], decode.string),
        )

      case account_result {
        Ok([handle]) -> {
          let challenge = crypto.random_string(32)
          let _ =
            sqlight.query(
              "INSERT INTO webauthn_challenges (challenge, did, type, expires_at) VALUES (?, ?, 'register', datetime('now', '+5 minutes'))",
              ctx.db,
              [sqlight.text(challenge), sqlight.text(user_did)],
              decode.at([0], decode.string),
            )

          let user_id =
            crypto.base64url_encode(bit_array.from_string(user_did))
          let rp_id = rp_id_from_request(req, ctx)
          let rp_name = case rp_id {
            "localhost" -> "Gleam PDS (dev)"
            _ -> "Gleam PDS"
          }

          // Get existing credentials to exclude
          let existing =
            sqlight.query(
              "SELECT credential_id FROM passkeys WHERE did = ?",
              ctx.db,
              [sqlight.text(user_did)],
              decode.at([0], decode.string),
            )
            |> result.unwrap([])

          let exclude_creds =
            list.map(existing, fn(cid) {
              json.object([
                #("type", json.string("public-key")),
                #("id", json.string(cid)),
              ])
            })

          response.json_response(
            200,
            json.object([
              #("challenge", json.string(challenge)),
              #(
                "rp",
                json.object([
                  #("name", json.string(rp_name)),
                  #("id", json.string(rp_id)),
                ]),
              ),
              #(
                "user",
                json.object([
                  #("id", json.string(user_id)),
                  #("name", json.string(handle)),
                  #("displayName", json.string(handle)),
                ]),
              ),
              #(
                "pubKeyCredParams",
                json.preprocessed_array([
                  json.object([
                    #("alg", json.int(-7)),
                    #("type", json.string("public-key")),
                  ]),
                  json.object([
                    #("alg", json.int(-257)),
                    #("type", json.string("public-key")),
                  ]),
                ]),
              ),
              #("timeout", json.int(120_000)),
              #(
                "excludeCredentials",
                json.preprocessed_array(exclude_creds),
              ),
              #(
                "authenticatorSelection",
                json.object([
                  #("residentKey", json.string("preferred")),
                  #("requireResidentKey", json.bool(False)),
                  #("userVerification", json.string("preferred")),
                ]),
              ),
              #("attestation", json.string("none")),
            ]),
          )
        }
        _ -> response.xrpc_error(400, "InvalidRequest", "Account not found")
      }
    }
  }
}

fn register_finish(req: Request, ctx: Context) -> Response {
  case server.get_auth_did_full(req, ctx) {
    Error(resp) -> resp
    Ok(user_did) -> {
      use body <- wisp.require_json(req)

      // Decode the credential response - try nested structure
      let nested_decoder = {
        use id <- decode.field("id", decode.string)
        use raw_id <- decode.field("rawId", decode.string)
        use resp <- decode.field("response", {
          use att_obj <- decode.field("attestationObject", decode.string)
          use cd <- decode.field("clientDataJSON", decode.string)
          decode.success(#(att_obj, cd))
        })
        decode.success(#(id, raw_id, Some(resp.0), Some(resp.1)))
      }

      let flat_decoder = {
        use id <- decode.field("id", decode.string)
        use raw_id <- decode.field("rawId", decode.string)
        decode.success(#(id, raw_id, None, None))
      }

      let parsed = case decode.run(body, nested_decoder) {
        Ok(v) -> Ok(v)
        Error(_) -> decode.run(body, flat_decoder)
      }

      case parsed {
        Error(_) ->
          response.xrpc_error(
            400,
            "InvalidRequest",
            "Invalid credential data",
          )
        Ok(#(_cred_id, raw_id, att_obj, client_data)) -> {
          // Verify a pending challenge exists
          let challenge_result =
            sqlight.query(
              "SELECT challenge FROM webauthn_challenges WHERE did = ? AND type = 'register' AND expires_at > datetime('now') ORDER BY created_at DESC LIMIT 1",
              ctx.db,
              [sqlight.text(user_did)],
              decode.at([0], decode.string),
            )

          case challenge_result {
            Ok([stored_challenge]) -> {
              let rp_id = rp_id_from_request(req, ctx)

              // C8 + C3(a): fully verify the attestation ceremony and extract a
              // REAL P-256 public key. If any of this fails we reject the
              // registration outright rather than storing a placeholder key.
              let verified = {
                use cd_b64 <- result.try(option.to_result(client_data, Nil))
                use att <- result.try(option.to_result(att_obj, Nil))
                use cd <- result.try(parse_client_data(cd_b64))
                use _ <- result.try(guard(cd.typ == "webauthn.create"))
                use _ <- result.try(guard(cd.challenge == stored_challenge))
                use _ <- result.try(guard(cd.origin == ctx.config.public_url))
                use parsed <- result.try(result.replace_error(
                  ffi_parse_attestation(att),
                  Nil,
                ))
                use pk <- result.try(result.replace_error(
                  decode.run(parsed, decode.at(["public_key"], decode.bit_array)),
                  Nil,
                ))
                use _ <- result.try(guard(bit_array.byte_size(pk) == 65))
                use rp_hash <- result.try(result.replace_error(
                  decode.run(
                    parsed,
                    decode.at(["rp_id_hash"], decode.bit_array),
                  ),
                  Nil,
                ))
                use _ <- result.try(guard(rp_hash == crypto.sha256_string(rp_id)))
                use up <- result.try(result.replace_error(
                  decode.run(parsed, decode.at(["user_present"], decode.int)),
                  Nil,
                ))
                use _ <- result.try(guard(up == 1))
                Ok(pk)
              }

              // Clean up challenge (single-use) regardless of outcome.
              let _ =
                sqlight.query(
                  "DELETE FROM webauthn_challenges WHERE did = ? AND type = 'register'",
                  ctx.db,
                  [sqlight.text(user_did)],
                  decode.at([0], decode.string),
                )

              case verified {
                Error(_) ->
                  response.xrpc_error(
                    400,
                    "InvalidRequest",
                    "WebAuthn registration verification failed (bad clientData, origin, challenge, rpId, or missing EC public key)",
                  )
                Ok(public_key) -> {
                  // Use the raw_id (base64url of credential ID bytes) as the
                  // stored ID. The browser sends `id`, the base64url encoding.
                  let stored_cred_id = raw_id
                  let passkey_id = crypto.random_string(16)
                  let _ =
                    sqlight.query(
                      "INSERT INTO passkeys (id, did, credential_id, public_key, sign_count) VALUES (?, ?, ?, ?, 0)",
                      ctx.db,
                      [
                        sqlight.text(passkey_id),
                        sqlight.text(user_did),
                        sqlight.text(stored_cred_id),
                        sqlight.blob(public_key),
                      ],
                      decode.at([0], decode.string),
                    )

                  response.json_response(
                    200,
                    json.object([
                      #("status", json.string("ok")),
                      #("credentialId", json.string(stored_cred_id)),
                    ]),
                  )
                }
              }
            }
            _ ->
              response.xrpc_error(
                400,
                "InvalidRequest",
                "No valid registration challenge found",
              )
          }
        }
      }
    }
  }
}

// -- Login --

fn login_begin(req: Request, ctx: Context) -> Response {
  use body <- wisp.require_json(req)

  let decoder = {
    use request_id <- decode.optional_field(
      "request_id",
      None,
      decode.optional(decode.string),
    )
    decode.success(request_id)
  }

  let request_id = case decode.run(body, decoder) {
    Ok(Some(rid)) -> rid
    _ -> ""
  }

  let challenge = crypto.random_string(32)
  let rp_id = rp_id_from_request(req, ctx)

  let _ =
    sqlight.query(
      "INSERT INTO webauthn_challenges (challenge, type, expires_at) VALUES (?, 'login', datetime('now', '+5 minutes'))",
      ctx.db,
      [sqlight.text(challenge)],
      decode.at([0], decode.string),
    )

  // C3(c): NEVER enumerate every user's credential IDs to an unauthenticated
  // caller. This is a discoverable-credential (resident key) login, so we send
  // an empty allowCredentials list and let the authenticator pick the resident
  // credential for this RP. The identity is then established by the signed
  // assertion, not by us handing out credential IDs.
  response.json_response(
    200,
    json.object([
      #("challenge", json.string(challenge)),
      #("rpId", json.string(rp_id)),
      #("allowCredentials", json.preprocessed_array([])),
      #("timeout", json.int(120_000)),
      #("userVerification", json.string("preferred")),
      #("requestId", json.string(request_id)),
    ]),
  )
}

fn login_finish(req: Request, ctx: Context) -> Response {
  use body <- wisp.require_json(req)

  // Try nested response structure (browser sends this way)
  let nested_decoder = {
    use request_id <- decode.optional_field(
      "request_id",
      None,
      decode.optional(decode.string),
    )
    use id <- decode.field("id", decode.string)
    use raw_id <- decode.field("rawId", decode.string)
    use resp <- decode.field("response", {
      use ad <- decode.field("authenticatorData", decode.string)
      use cd <- decode.field("clientDataJSON", decode.string)
      use sig <- decode.field("signature", decode.string)
      decode.success(#(ad, cd, sig))
    })
    decode.success(#(request_id, id, raw_id, resp.0, resp.1, resp.2))
  }

  let flat_decoder = {
    use request_id <- decode.optional_field(
      "request_id",
      None,
      decode.optional(decode.string),
    )
    use id <- decode.field("id", decode.string)
    use raw_id <- decode.field("rawId", decode.string)
    use auth_data <- decode.field("authenticatorData", decode.string)
    use client_data <- decode.field("clientDataJSON", decode.string)
    use signature <- decode.field("signature", decode.string)
    decode.success(#(request_id, id, raw_id, auth_data, client_data, signature))
  }

  let parsed = case decode.run(body, nested_decoder) {
    Ok(v) -> Ok(v)
    Error(_) -> decode.run(body, flat_decoder)
  }

  case parsed {
    Error(_) ->
      response.xrpc_error(400, "InvalidRequest", "Invalid assertion data")
    Ok(#(request_id, _cred_id, raw_id, auth_data, client_data, signature)) -> {
      // Look up passkey by raw_id (what we stored during registration)
      let passkey_result =
        sqlight.query(
          "SELECT p.did, p.public_key, p.sign_count, a.handle FROM passkeys p JOIN accounts a ON p.did = a.did WHERE p.credential_id = ? LIMIT 1",
          ctx.db,
          [sqlight.text(raw_id)],
          {
            use d <- decode.field(0, decode.string)
            use pk <- decode.field(1, decode.bit_array)
            use sc <- decode.field(2, decode.int)
            use h <- decode.field(3, decode.string)
            decode.success(#(d, pk, sc, h))
          },
        )

      case passkey_result {
        Ok([#(user_did, public_key, stored_sign_count, handle)]) -> {
          let rp_id = rp_id_from_request(req, ctx)

          let verified = {
            // C3(b): a placeholder key must NEVER authenticate. Require a real
            // 65-byte uncompressed EC public key.
            use _ <- result.try(guard(bit_array.byte_size(public_key) == 65))
            // C8: verify clientDataJSON type + origin.
            use cd <- result.try(parse_client_data(client_data))
            use _ <- result.try(guard(cd.typ == "webauthn.get"))
            use _ <- result.try(guard(cd.origin == ctx.config.public_url))
            // C8: bind to the stored login challenge for THIS ceremony
            // (single-use). Previously the login challenge was ignored entirely.
            use _ <- result.try(consume_login_challenge(ctx, cd.challenge))
            // C8: verify authenticatorData rpIdHash and user-presence bit.
            use ad <- result.try(parse_auth_data(auth_data))
            use _ <- result.try(guard(
              ad.rp_id_hash == crypto.sha256_string(rp_id),
            ))
            use _ <- result.try(guard(ad.user_present))
            // S1: reject a counter that went backwards (cloned authenticator).
            use _ <- result.try(guard(counter_ok(
              stored_sign_count,
              ad.sign_count,
            )))
            // C3(b): always verify the assertion signature against the real key.
            use _ <- result.try(guard(ffi_verify_assertion(
              auth_data,
              client_data,
              signature,
              public_key,
            )))
            Ok(ad.sign_count)
          }

          case verified {
            Ok(new_count) -> {
              // S1: persist the new (higher) counter value.
              let _ =
                sqlight.query(
                  "UPDATE passkeys SET sign_count = ? WHERE credential_id = ?",
                  ctx.db,
                  [sqlight.int(new_count), sqlight.text(raw_id)],
                  decode.at([0], decode.string),
                )

              complete_login(request_id, user_did, handle, ctx)
            }
            Error(_) ->
              response.xrpc_error(
                401,
                "AuthenticationRequired",
                "Passkey verification failed",
              )
          }
        }
        _ ->
          response.xrpc_error(
            401,
            "AuthenticationRequired",
            "Passkey not recognized",
          )
      }
    }
  }
}

fn complete_login(
  request_id: Option(String),
  user_did: String,
  handle: String,
  ctx: Context,
) -> Response {
  case request_id {
    Some(rid) if rid != "" -> {
      // OAuth flow: generate code; return redirect URL for fetch-based passkey
      // login (the authorize page navigates client-side).
      let code = crypto.random_string(32)
      let _ =
        sqlight.query(
          "UPDATE oauth_auth_requests SET did = ?, code = ? WHERE id = ?",
          ctx.db,
          [
            sqlight.text(user_did),
            sqlight.text(code),
            sqlight.text(rid),
          ],
          decode.at([0], decode.string),
        )

      let auth_req =
        sqlight.query(
          "SELECT redirect_uri, state FROM oauth_auth_requests WHERE id = ? LIMIT 1",
          ctx.db,
          [sqlight.text(rid)],
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
          response.json_response(
            200,
            json.object([#("redirect", json.string(redirect))]),
          )
        }
        _ ->
          response.xrpc_error(
            400,
            "invalid_request",
            "OAuth authorization request not found",
          )
      }
    }
    _ -> {
      // Direct login. Route through the shared session creator so the session
      // is persisted (and therefore revocable, C4) rather than being a
      // stateless signature-only token.
      let session = server.create_session_for_did(user_did, ctx)
      response.json_response(
        200,
        json.object([
          #("accessJwt", json.string(session.access_jwt)),
          #("refreshJwt", json.string(session.refresh_jwt)),
          #("handle", json.string(handle)),
          #("did", json.string(user_did)),
        ]),
      )
    }
  }
}

// -- Helpers --

/// Derive the RP ID from the request's Host header.
/// WebAuthn requires the RP ID to match the browsing context domain.
fn rp_id_from_request(req: Request, ctx: Context) -> String {
  let host =
    list.key_find(req.headers, "host")
    |> result.lazy_unwrap(fn() {
      list.key_find(req.headers, "x-forwarded-host")
      |> result.unwrap(ctx.config.hostname)
    })
  // Strip port
  case string.split(host, ":") {
    [h, ..] -> h
    _ -> host
  }
}

fn guard(cond: Bool) -> Result(Nil, Nil) {
  case cond {
    True -> Ok(Nil)
    False -> Error(Nil)
  }
}

/// WebAuthn signature-counter rule: if both the stored and incoming counters
/// are 0 the authenticator does not support counters (allow); otherwise the
/// incoming counter must be strictly greater than the stored one.
fn counter_ok(stored: Int, incoming: Int) -> Bool {
  case stored == 0 && incoming == 0 {
    True -> True
    False -> incoming > stored
  }
}

/// Verify that the challenge echoed in clientDataJSON corresponds to a stored,
/// unexpired login challenge, and consume it (single use).
fn consume_login_challenge(ctx: Context, challenge: String) -> Result(Nil, Nil) {
  let found =
    sqlight.query(
      "SELECT challenge FROM webauthn_challenges WHERE challenge = ? AND type = 'login' AND expires_at > datetime('now') LIMIT 1",
      ctx.db,
      [sqlight.text(challenge)],
      decode.at([0], decode.string),
    )
  case found {
    Ok([_]) -> {
      let _ =
        sqlight.query(
          "DELETE FROM webauthn_challenges WHERE challenge = ? AND type = 'login'",
          ctx.db,
          [sqlight.text(challenge)],
          decode.at([0], decode.string),
        )
      Ok(Nil)
    }
    _ -> Error(Nil)
  }
}
