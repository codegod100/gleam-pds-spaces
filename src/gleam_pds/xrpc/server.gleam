/// XRPC com.atproto.server.* handlers

import gleam_pds/context.{type Context}
import gleam_pds/crypto
import gleam_pds/firehose
import gleam_pds/plc
import gleam_pds/ratelimit
import gleam_pds/turnstile
import gleam_pds/web/response
import gleam/bit_array
import gleam/dynamic/decode
import gleam/http
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import sqlight
import wisp.{type Request, type Response}

@external(erlang, "gleam_pds_crypto_ffi", "public_key_to_did_key")
fn public_key_to_did_key(public_key: BitArray) -> String

@external(erlang, "gleam_pds_plc_ffi", "der_to_raw_es256")
fn der_to_raw(der_sig: BitArray) -> BitArray

@external(erlang, "gleam_pds_mst_ffi", "init_repo_mst")
fn init_repo_mst(db: sqlight.Connection, did: String) -> String

/// Build a DID document for inclusion in session/account responses
pub fn build_did_doc(
  user_did: String,
  handle: String,
  public_key: BitArray,
  public_url: String,
) -> json.Json {
  let did_key = public_key_to_did_key(public_key)
  // did:key looks like "did:key:zDnae...", multibase is the part after "did:key:"
  let multibase = string.drop_start(did_key, 8)
  json.object([
    #("@context", json.array(
      ["https://www.w3.org/ns/did/v1",
       "https://w3id.org/security/multikey/v1",
       "https://w3id.org/security/suites/ecdsa-2019/v1"],
      json.string,
    )),
    #("id", json.string(user_did)),
    #("alsoKnownAs", json.array(["at://" <> handle], json.string)),
    #("verificationMethod", json.preprocessed_array([
      json.object([
        #("id", json.string(user_did <> "#atproto")),
        #("type", json.string("Multikey")),
        #("controller", json.string(user_did)),
        #("publicKeyMultibase", json.string(multibase)),
      ]),
    ])),
    #("service", json.preprocessed_array([
      json.object([
        #("id", json.string("#atproto_pds")),
        #("type", json.string("AtprotoPersonalDataServer")),
        #("serviceEndpoint", json.string(public_url)),
      ]),
    ])),
  ])
}

/// Look up the public signing key for a DID from the repos table
pub fn get_public_key_for_did(
  user_did: String,
  ctx: Context,
) -> Result(BitArray, Nil) {
  let result =
    sqlight.query(
      "SELECT signing_key_public FROM repos WHERE did = ? LIMIT 1",
      ctx.db,
      [sqlight.text(user_did)],
      decode.at([0], decode.bit_array),
    )
  case result {
    Ok([pk]) -> Ok(pk)
    _ -> Error(Nil)
  }
}

pub fn describe_server(_req: Request, ctx: Context) -> Response {
  let server_did =
    "did:web:" <> string.replace(ctx.config.hostname, ":", "%3A")
  response.json_response(
    200,
    json.object([
      #("did", json.string(server_did)),
      #(
        "availableUserDomains",
        json.array([ctx.config.handle_domain], json.string),
      ),
      #("inviteCodeRequired", json.bool(False)),
      #("phoneVerificationRequired", json.bool(False)),
      #("links", json.object([])),
    ]),
  )
}

pub fn create_account(req: Request, ctx: Context) -> Response {
  case ctx.config.signups_disabled {
    True ->
      response.xrpc_error(
        403,
        "SignupDisabled",
        "Account creation is currently disabled on this server.",
      )
    False -> do_create_account(req, ctx)
  }
}

fn do_create_account(req: Request, ctx: Context) -> Response {
  use body <- wisp.require_json(req)

  let decoder = {
    use handle <- decode.field("handle", decode.string)
    use email <- decode.optional_field("email", None, decode.optional(decode.string))
    use password <- decode.optional_field("password", None, decode.optional(decode.string))
    use turnstile_token <- decode.optional_field(
      "turnstileToken",
      None,
      decode.optional(decode.string),
    )
    decode.success(#(handle, email, password, turnstile_token))
  }

  case decode.run(body, decoder) {
    Error(_) ->
      response.xrpc_error(400, "InvalidRequest", "Invalid request body")
    Ok(#(handle, email, password, turnstile_token)) -> {
      case check_turnstile(ctx, req, turnstile_token) {
        Error(resp) -> resp
        Ok(_) -> do_create_account_verified(req, ctx, handle, email, password)
      }
    }
  }
}

/// Reject before any of the expensive work below (key generation, PLC
/// registration) if Turnstile is configured and the widget response is
/// missing or Cloudflare rejects it. A no-op when Turnstile isn't configured
/// on this server (GLEAM_PDS_TURNSTILE_SECRET_KEY unset).
fn check_turnstile(
  ctx: Context,
  req: Request,
  token: option.Option(String),
) -> Result(Nil, Response) {
  case ctx.config.turnstile_secret_key, token {
    None, _ -> Ok(Nil)
    Some(_), None ->
      Error(response.xrpc_error(
        400,
        "InvalidRequest",
        "Captcha verification is required to create an account.",
      ))
    Some(_), Some(t) -> {
      let remote_ip = ratelimit.client_ip(req)
      case turnstile.verify(ctx.config.turnstile_secret_key, t, remote_ip) {
        Ok(_) -> Ok(Nil)
        Error(_) ->
          Error(response.xrpc_error(
            400,
            "InvalidRequest",
            "Captcha verification failed. Please try again.",
          ))
      }
    }
  }
}

fn do_create_account_verified(
  req: Request,
  ctx: Context,
  handle: String,
  email: option.Option(String),
  password: option.Option(String),
) -> Response {
  {
    // Validate handle
    let full_handle = case string.contains(handle, ".") {
        True -> handle
        False -> handle <> "." <> ctx.config.handle_domain
      }

      // Hash password
      let pw_hash = case password {
        Some(pw) -> Some(crypto.hash_password(pw))
        None -> None
      }

      // Generate signing keys
      let key_pair = crypto.generate_p256_keypair()

      // Register DID with PLC directory
      let did_result =
        plc.create_and_register(
          key_pair.private_key,
          key_pair.public_key,
          full_handle,
          ctx.config.public_url,
          ctx.config.rotation_key,
        )

      case did_result {
        Error(err) ->
          response.xrpc_error(500, "InternalError", "DID registration failed: " <> err)
        Ok(user_did) -> {
          // Insert account
          let account_result =
            sqlight.query(
              "INSERT INTO accounts (did, handle, email, password_hash) VALUES (?, ?, ?, ?) RETURNING did",
              ctx.db,
              [
                sqlight.text(user_did),
                sqlight.text(full_handle),
                case email {
                  Some(e) -> sqlight.text(e)
                  None -> sqlight.null()
                },
                case pw_hash {
                  Some(h) -> sqlight.text(h)
                  None -> sqlight.null()
                },
              ],
              decode.at([0], decode.string),
            )

          case account_result {
            Error(_) ->
              response.xrpc_error(
                400,
                "HandleNotAvailable",
                "Handle already taken: " <> full_handle,
              )
            Ok(_) -> {
              // Create repo
              let _ =
                sqlight.query(
                  "INSERT INTO repos (did, signing_key_private, signing_key_public) VALUES (?, ?, ?)",
                  ctx.db,
                  [
                    sqlight.text(user_did),
                    sqlight.blob(key_pair.private_key),
                    sqlight.blob(key_pair.public_key),
                  ],
                  decode.at([0], decode.string),
                )

              let _ = init_repo_mst(ctx.db, user_did)

              // Announce the new account to the firehose (#account + #identity)
              // so relays begin indexing it.
              firehose.emit_account_created(ctx.firehose, user_did, full_handle)

              // Create session
              let session = create_session_for_did(user_did, ctx)
              let did_doc = build_did_doc(
                user_did,
                full_handle,
                key_pair.public_key,
                ctx.config.public_url,
              )

              response.json_response(
                200,
                json.object([
                  #("accessJwt", json.string(session.access_jwt)),
                  #("refreshJwt", json.string(session.refresh_jwt)),
                  #("handle", json.string(full_handle)),
                  #("did", json.string(user_did)),
                  #("didDoc", did_doc),
                ]),
              )
            }
          }
        }
      }
  }
}

pub type Session {
  Session(id: String, access_jwt: String, refresh_jwt: String)
}

/// Scope string for a session created from the account's main password.
pub const scope_access: String = "com.atproto.access"

/// Scope string for a session created from an app password. App-password
/// sessions can read and write records but must not perform account
/// management (creating app passwords, deleting/activating the account,
/// rotating the handle or PLC identity, registering passkeys).
pub const scope_app_pass: String = "com.atproto.appPass"

pub fn create_session_for_did(user_did: String, ctx: Context) -> Session {
  create_session_scoped(user_did, ctx, scope_access)
}

pub fn create_session_scoped(
  user_did: String,
  ctx: Context,
  access_scope: String,
) -> Session {
  let session_id = crypto.random_string(32)
  let now_ts = crypto.timestamp_microseconds() / 1_000_000
  let expires_ts = now_ts + 7200
  let refresh_expires_ts = now_ts + 86_400 * 90

  let access_jwt =
    crypto.create_jwt(
      [
        #("scope", json.string(access_scope)),
        #("sub", json.string(user_did)),
        #("iat", json.int(now_ts)),
        #("exp", json.int(expires_ts)),
      ],
      ctx.config.secret_key,
    )

  let refresh_jwt =
    crypto.create_jwt(
      [
        #("scope", json.string("com.atproto.refresh")),
        #("sub", json.string(user_did)),
        #("iat", json.int(now_ts)),
        #("exp", json.int(refresh_expires_ts)),
        #("jti", json.string(session_id)),
      ],
      ctx.config.secret_key,
    )

  let _ =
    sqlight.query(
      "INSERT INTO sessions (id, did, access_jwt, refresh_jwt, scope, expires_at) VALUES (?, ?, ?, ?, ?, datetime('now', '+2 hours'))",
      ctx.db,
      [
        sqlight.text(session_id),
        sqlight.text(user_did),
        sqlight.text(access_jwt),
        sqlight.text(refresh_jwt),
        sqlight.text(access_scope),
      ],
      decode.at([0], decode.string),
    )

  Session(
    id: session_id,
    access_jwt: access_jwt,
    refresh_jwt: refresh_jwt,
  )
}

pub fn create_session(req: Request, ctx: Context) -> Response {
  use body <- wisp.require_json(req)

  let decoder = {
    use identifier <- decode.field("identifier", decode.string)
    use password <- decode.field("password", decode.string)
    decode.success(#(identifier, password))
  }

  case decode.run(body, decoder) {
    Error(_) ->
      response.xrpc_error(
        400,
        "InvalidRequest",
        "Missing identifier or password",
      )
    Ok(#(identifier, password)) -> {
      let account_decoder = {
        use d <- decode.field(0, decode.string)
        use h <- decode.field(1, decode.string)
        use pw <- decode.field(2, decode.optional(decode.string))
        use deactivated <- decode.field(3, decode.optional(decode.string))
        decode.success(#(d, h, pw, deactivated))
      }

      // Accept handle, DID, or email as the identifier (case-insensitive for
      // handle/email, DIDs are case-sensitive).
      let account_result =
        sqlight.query(
          "SELECT did, handle, password_hash, deactivated_at FROM accounts
           WHERE lower(handle) = lower(?) OR did = ? OR lower(email) = lower(?)
           LIMIT 1",
          ctx.db,
          [
            sqlight.text(identifier),
            sqlight.text(identifier),
            sqlight.text(identifier),
          ],
          account_decoder,
        )

      case account_result {
        Ok([#(user_did, handle, pw_hash, deactivated)]) -> {
          // Verify against the account password first, then any app password.
          case verify_login(ctx, user_did, password, pw_hash) {
            Error(_) ->
              response.xrpc_error(
                401,
                "AuthenticationRequired",
                "Invalid identifier or password",
              )
            Ok(access_scope) -> {
              // A deactivated account may still sign in — otherwise it could
              // never call activateAccount — but the session is marked
              // inactive and get_auth_did refuses it for anything else.
              let active = case deactivated {
                Some(_) -> False
                None -> True
              }
              let session = create_session_scoped(user_did, ctx, access_scope)
              let did_doc_field = case get_public_key_for_did(user_did, ctx) {
                Ok(pk) -> [
                  #("didDoc", build_did_doc(user_did, handle, pk, ctx.config.public_url)),
                ]
                Error(_) -> []
              }
              response.json_response(
                200,
                json.object(list.flatten([
                  [
                    #("accessJwt", json.string(session.access_jwt)),
                    #("refreshJwt", json.string(session.refresh_jwt)),
                    #("handle", json.string(handle)),
                    #("did", json.string(user_did)),
                    #("active", json.bool(active)),
                  ],
                  status_field(active),
                  did_doc_field,
                ])),
              )
            }
          }
        }
        _ ->
          response.xrpc_error(
            401,
            "AuthenticationRequired",
            "Invalid identifier or password",
          )
      }
    }
  }
}

/// `status` is only present when the account is not active.
fn status_field(active: Bool) -> List(#(String, json.Json)) {
  case active {
    True -> []
    False -> [#("status", json.string("deactivated"))]
  }
}

/// Verify a login password against the account password and, failing that,
/// every app password on the account. Returns the scope the resulting session
/// should carry.
fn verify_login(
  ctx: Context,
  user_did: String,
  password: String,
  account_hash: option.Option(String),
) -> Result(String, Nil) {
  let account_ok = case account_hash {
    Some(h) -> crypto.verify_password(password, h)
    None -> False
  }
  case account_ok {
    True -> Ok(scope_access)
    False ->
      case verify_app_password(ctx, user_did, password) {
        True -> Ok(scope_app_pass)
        False -> Error(Nil)
      }
  }
}

fn verify_app_password(
  ctx: Context,
  user_did: String,
  password: String,
) -> Bool {
  let candidates = app_password_candidates(password)
  case candidates {
    [] -> False
    _ -> {
      let hashes =
        sqlight.query(
          "SELECT password_hash FROM app_passwords WHERE did = ?",
          ctx.db,
          [sqlight.text(user_did)],
          decode.at([0], decode.optional(decode.string)),
        )
      case hashes {
        Ok(rows) ->
          list.any(rows, fn(row) {
            case row {
              Some(hash) ->
                list.any(candidates, fn(c) { crypto.verify_password(c, hash) })
              None -> False
            }
          })
        Error(_) -> False
      }
    }
  }
}

/// App passwords are issued as lowercase `xxxx-xxxx-xxxx-xxxx`. Clients often
/// paste them with different casing or with the dashes stripped, so accept
/// those forms too. An empty password never matches.
fn app_password_candidates(password: String) -> List(String) {
  let trimmed = string.trim(password)
  case trimmed {
    "" -> []
    _ -> {
      let lowered = string.lowercase(trimmed)
      let stripped = string.replace(lowered, "-", "")
      let dashed = case string.length(stripped) == 16 {
        True ->
          string.slice(stripped, 0, 4)
          <> "-"
          <> string.slice(stripped, 4, 4)
          <> "-"
          <> string.slice(stripped, 8, 4)
          <> "-"
          <> string.slice(stripped, 12, 4)
        False -> lowered
      }
      [trimmed, lowered, dashed]
      |> list.unique
    }
  }
}

pub fn get_session(req: Request, ctx: Context) -> Response {
  // Deactivated accounts may inspect their own session (the client needs it to
  // discover the deactivated status and offer reactivation).
  case get_auth_did_any_status(req, ctx) {
    Error(resp) -> resp
    Ok(user_did) -> {
      let account_decoder = {
        use h <- decode.field(0, decode.string)
        use e <- decode.field(1, decode.optional(decode.string))
        use d <- decode.field(2, decode.optional(decode.string))
        decode.success(#(h, e, d))
      }

      let account_result =
        sqlight.query(
          "SELECT handle, email, deactivated_at FROM accounts WHERE did = ? LIMIT 1",
          ctx.db,
          [sqlight.text(user_did)],
          account_decoder,
        )

      case account_result {
        Ok([#(handle, email, deactivated)]) -> {
          let active = case deactivated {
            Some(_) -> False
            None -> True
          }
          let did_doc_field = case get_public_key_for_did(user_did, ctx) {
            Ok(pk) -> [
              #("didDoc", build_did_doc(user_did, handle, pk, ctx.config.public_url)),
            ]
            Error(_) -> []
          }
          response.json_response(
            200,
            json.object(list.flatten([
              [
                #("handle", json.string(handle)),
                #("did", json.string(user_did)),
                #(
                  "email",
                  case email {
                    Some(e) -> json.string(e)
                    None -> json.null()
                  },
                ),
                #("emailConfirmed", json.bool(True)),
                #("active", json.bool(active)),
              ],
              status_field(active),
              did_doc_field,
            ])),
          )
        }
        _ ->
          response.xrpc_error(
            401,
            "AuthenticationRequired",
            "Invalid session",
          )
      }
    }
  }
}

pub fn refresh_session(req: Request, ctx: Context) -> Response {
  case get_bearer_token(req) {
    Error(_) ->
      response.xrpc_error(
        401,
        "AuthenticationRequired",
        "Missing auth token",
      )
    Ok(token) -> {
      // C2: verify signature + enforce exp. C5: require refresh scope.
      case crypto.verify_jwt(token, ctx.config.secret_key) {
        Error(crypto.ExpiredToken) ->
          response.xrpc_error(401, "ExpiredToken", "Token expired")
        Error(_) ->
          response.xrpc_error(401, "InvalidToken", "Invalid token")
        Ok(claims) -> {
          case claims.scope, claims.sub, claims.jti {
            Some("com.atproto.refresh"), Some(user_did), Some(jti) -> {
              // C4: a deleted session's refresh token must stop working.
              case session_scope(ctx, jti) {
                Error(_) ->
                  response.xrpc_error(
                    401,
                    "ExpiredToken",
                    "Session has been revoked",
                  )
                Ok(access_scope) -> {
                  // Rotate: invalidate the old session, issue a new one with
                  // the same scope (an app-password session must not be able
                  // to refresh itself into a full-access one).
                  let _ =
                    sqlight.query(
                      "DELETE FROM sessions WHERE id = ?",
                      ctx.db,
                      [sqlight.text(jti)],
                      decode.at([0], decode.string),
                    )
                  let session =
                    create_session_scoped(user_did, ctx, access_scope)
                  response.json_response(
                    200,
                    json.object([
                      #("accessJwt", json.string(session.access_jwt)),
                      #("refreshJwt", json.string(session.refresh_jwt)),
                      #("handle", json.string("")),
                      #("did", json.string(user_did)),
                    ]),
                  )
                }
              }
            }
            _, _, _ ->
              response.xrpc_error(
                401,
                "InvalidToken",
                "Not a refresh token",
              )
          }
        }
      }
    }
  }
}

pub fn delete_session(req: Request, ctx: Context) -> Response {
  case get_bearer_token(req) {
    Error(_) -> wisp.ok()
    Ok(token) -> {
      case crypto.verify_jwt(token, ctx.config.secret_key) {
        Ok(claims) ->
          case claims.jti {
            Some(session_id) -> {
              let _ =
                sqlight.query(
                  "DELETE FROM sessions WHERE id = ?",
                  ctx.db,
                  [sqlight.text(session_id)],
                  decode.at([0], decode.string),
                )
              wisp.ok()
            }
            None -> wisp.ok()
          }
        Error(_) -> wisp.ok()
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

pub fn get_bearer_token(req: Request) -> Result(String, Nil) {
  case list.key_find(req.headers, "authorization") {
    Ok(auth) -> {
      case string.starts_with(auth, "Bearer ") {
        True -> Ok(string.drop_start(auth, 7))
        False ->
          case string.starts_with(auth, "DPoP ") {
            True -> Ok(string.drop_start(auth, 5))
            False -> Error(Nil)
          }
      }
    }
    Error(_) -> Error(Nil)
  }
}

/// com.atproto.server.getServiceAuth
pub fn get_service_auth(req: Request, ctx: Context) -> Response {
  case get_auth_did(req, ctx) {
    Error(resp) -> resp
    Ok(user_did) -> {
      let query = wisp.get_query(req)
      let aud = list.key_find(query, "aud")
      let lxm =
        list.key_find(query, "lxm")
        |> result.unwrap("")

      case aud {
        Error(_) ->
          response.xrpc_error(
            400,
            "InvalidRequest",
            "Missing required parameter: aud",
          )
        Ok(aud_val) -> {
          // Get the user's signing key
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

              let payload_fields = [
                #("iss", json.string(user_did)),
                #("aud", json.string(aud_val)),
                #("iat", json.int(now)),
                #("exp", json.int(exp)),
                #("jti", json.string(jti)),
              ]
              let payload_fields = case lxm {
                "" -> payload_fields
                l -> list.append(payload_fields, [#("lxm", json.string(l))])
              }

              let payload = json.to_string(json.object(payload_fields))

              let header_b64 =
                crypto.base64url_encode(bit_array.from_string(header))
              let payload_b64 =
                crypto.base64url_encode(bit_array.from_string(payload))
              let signing_input = header_b64 <> "." <> payload_b64

              let der_sig =
                crypto.sign_es256(
                  bit_array.from_string(signing_input),
                  private_key,
                )
              let raw_sig = der_to_raw(der_sig)
              let sig_b64 = crypto.base64url_encode(raw_sig)

              let token = signing_input <> "." <> sig_b64

              response.json_response(
                200,
                json.object([
                  #("token", json.string(token)),
                ]),
              )
            }
            _ ->
              response.xrpc_error(
                500,
                "InternalError",
                "No signing key found",
              )
          }
        }
      }
    }
  }
}

/// What a credential is allowed to do. App-password sessions can read and
/// write repo content but must not manage the account or its identity.
pub type AuthScope {
  FullAccess
  AppPassword
}

pub type Auth {
  Auth(did: String, scope: AuthScope, deactivated: Bool)
}

/// Standard authentication: rejects deactivated accounts, accepts both
/// full-access and app-password credentials.
pub fn get_auth_did(req: Request, ctx: Context) -> Result(String, Response) {
  require_auth(req, ctx, True, False)
}

/// Authentication for account/identity management: rejects app-password
/// credentials as well as deactivated accounts.
pub fn get_auth_did_full(req: Request, ctx: Context) -> Result(String, Response) {
  require_auth(req, ctx, False, False)
}

/// Authentication for endpoints a deactivated account must still reach
/// (getAccountStatus).
pub fn get_auth_did_any_status(
  req: Request,
  ctx: Context,
) -> Result(String, Response) {
  require_auth(req, ctx, True, True)
}

/// Authentication for management endpoints a deactivated account must still
/// reach (activateAccount, deleteAccount) — full access required.
pub fn get_auth_did_full_any_status(
  req: Request,
  ctx: Context,
) -> Result(String, Response) {
  require_auth(req, ctx, False, True)
}

fn require_auth(
  req: Request,
  ctx: Context,
  allow_app_password: Bool,
  allow_deactivated: Bool,
) -> Result(String, Response) {
  case authenticate(req, ctx) {
    Error(resp) -> Error(resp)
    Ok(auth) ->
      case auth.scope, allow_app_password {
        AppPassword, False ->
          Error(response.xrpc_error(
            403,
            "InvalidToken",
            "App passwords cannot be used for account management. Sign in with your main password.",
          ))
        _, _ ->
          case auth.deactivated, allow_deactivated {
            True, False ->
              Error(response.xrpc_error(
                400,
                "AccountDeactivated",
                "Account is deactivated",
              ))
            _, _ -> Ok(auth.did)
          }
      }
  }
}

/// Resolve the credential on the request to an account, its scope, and its
/// activation state. Callers should prefer the `get_auth_did*` wrappers, which
/// apply the scope / deactivation policy.
pub fn authenticate(req: Request, ctx: Context) -> Result(Auth, Response) {
  case authenticate_credential(req, ctx) {
    Error(resp) -> Error(resp)
    Ok(#(user_did, scope)) ->
      Ok(Auth(
        did: user_did,
        scope: scope,
        deactivated: account_is_deactivated(ctx, user_did),
      ))
  }
}

/// True only when the account exists and carries a deactivation timestamp. A
/// missing row is not treated as deactivated: deleting an account cascades
/// away its sessions and tokens, so no live credential can reach here.
fn account_is_deactivated(ctx: Context, user_did: String) -> Bool {
  case
    sqlight.query(
      "SELECT deactivated_at FROM accounts WHERE did = ? LIMIT 1",
      ctx.db,
      [sqlight.text(user_did)],
      decode.at([0], decode.optional(decode.string)),
    )
  {
    Ok([Some(_)]) -> True
    _ -> False
  }
}

fn authenticate_credential(
  req: Request,
  ctx: Context,
) -> Result(#(String, AuthScope), Response) {
  case get_bearer_token(req) {
    Error(_) ->
      Error(response.xrpc_error(
        401,
        "AuthenticationRequired",
        "Authentication required",
      ))
    Ok(token) -> {
      // First try: verify as HMAC JWT (session tokens + OAuth JWTs).
      case crypto.verify_jwt(token, ctx.config.secret_key) {
        Ok(claims) -> {
          case claims.sub {
            None ->
              Error(response.xrpc_error(401, "InvalidToken", "Invalid token"))
            Some(user_did) ->
              case claims.client_id {
                // OAuth access token (JWT, may be DPoP-bound).
                Some(_) -> authorize_oauth_token(req, ctx, token, user_did, claims)
                // Session access token.
                None -> authorize_session_token(ctx, token, user_did, claims)
              }
          }
        }
        Error(crypto.ExpiredToken) ->
          Error(response.xrpc_error(401, "ExpiredToken", "Token expired"))
        Error(_) -> {
          // Second try: look up as an opaque (legacy) OAuth access token.
          let result =
            sqlight.query(
              "SELECT did FROM oauth_tokens WHERE access_token = ? AND expires_at > datetime('now') LIMIT 1",
              ctx.db,
              [sqlight.text(token)],
              decode.at([0], decode.string),
            )
          case result {
            Ok([user_did]) -> Ok(#(user_did, FullAccess))
            _ ->
              Error(response.xrpc_error(
                401,
                "ExpiredToken",
                "Token expired or invalid",
              ))
          }
        }
      }
    }
  }
}

/// Session access token: enforce access scope (C5) and revocation (C4).
fn authorize_session_token(
  ctx: Context,
  token: String,
  user_did: String,
  claims: crypto.Claims,
) -> Result(#(String, AuthScope), Response) {
  let scope = case claims.scope {
    // C5: refresh-scoped tokens must not authenticate resource access.
    Some("com.atproto.access") -> Ok(FullAccess)
    Some("com.atproto.appPass") -> Ok(AppPassword)
    _ -> Error(Nil)
  }
  case scope {
    Ok(auth_scope) -> {
      // C4: a deleted session must stop authenticating.
      case session_access_jwt_exists(ctx, token) {
        True -> Ok(#(user_did, auth_scope))
        False ->
          Error(response.xrpc_error(
            401,
            "ExpiredToken",
            "Session has been revoked",
          ))
      }
    }
    Error(_) ->
      Error(response.xrpc_error(
        401,
        "InvalidToken",
        "Refresh tokens cannot be used to access resources",
      ))
  }
}

/// OAuth access token: enforce revocation/expiry (C4) and DPoP binding (C6).
fn authorize_oauth_token(
  req: Request,
  ctx: Context,
  token: String,
  user_did: String,
  claims: crypto.Claims,
) -> Result(#(String, AuthScope), Response) {
  // C4: the token row must still exist and not be expired.
  let valid =
    case
      sqlight.query(
        "SELECT did FROM oauth_tokens WHERE access_token = ? AND expires_at > datetime('now') LIMIT 1",
        ctx.db,
        [sqlight.text(token)],
        decode.at([0], decode.string),
      )
    {
      Ok([_]) -> True
      _ -> False
    }
  case valid {
    False ->
      Error(response.xrpc_error(
        401,
        "ExpiredToken",
        "Token expired or revoked",
      ))
    True ->
      // C6: if the token is DPoP-bound, require a matching, valid DPoP proof.
      case claims.cnf_jkt {
        None -> Ok(#(user_did, FullAccess))
        Some(jkt) ->
          case validate_dpop_resource(req, ctx, token, jkt) {
            Ok(_) -> Ok(#(user_did, FullAccess))
            Error(resp) -> Error(resp)
          }
      }
  }
}

fn validate_dpop_resource(
  req: Request,
  ctx: Context,
  token: String,
  jkt: String,
) -> Result(Nil, Response) {
  case list.key_find(req.headers, "dpop") {
    Error(_) ->
      Error(response.xrpc_error(
        401,
        "InvalidToken",
        "DPoP proof required for this token",
      ))
    Ok(proof) -> {
      let method = string.uppercase(http.method_to_string(req.method))
      let htu = ctx.config.public_url <> req.path
      let nonces = crypto.dpop_nonces_accepted(ctx.config.secret_key)
      case crypto.verify_dpop(proof, method, htu, Some(token), nonces) {
        Ok(proof_jkt) ->
          case proof_jkt == jkt {
            True -> Ok(Nil)
            False ->
              Error(response.xrpc_error(
                401,
                "InvalidToken",
                "DPoP proof key does not match the bound token",
              ))
          }
        // RFC 9449 §9: resource-server nonce errors use the use_dpop_nonce
        // error code with a fresh DPoP-Nonce header so the client retries.
        Error(crypto.DpopBadNonce) ->
          Error(
            response.xrpc_error(
              401,
              "use_dpop_nonce",
              "Resource server requires nonce in DPoP proof",
            )
            |> wisp.set_header(
              "dpop-nonce",
              crypto.dpop_nonce(ctx.config.secret_key),
            )
            |> wisp.set_header(
              "www-authenticate",
              "DPoP error=\"use_dpop_nonce\"",
            ),
          )
        Error(_) ->
          Error(response.xrpc_error(
            401,
            "InvalidToken",
            "Invalid DPoP proof",
          ))
      }
    }
  }
}

fn session_access_jwt_exists(ctx: Context, token: String) -> Bool {
  case
    sqlight.query(
      "SELECT id FROM sessions WHERE access_jwt = ? LIMIT 1",
      ctx.db,
      [sqlight.text(token)],
      decode.at([0], decode.string),
    )
  {
    Ok([_]) -> True
    _ -> False
  }
}

/// The access scope recorded for a session row, or Error if the session has
/// been revoked. Rows written before the `scope` column existed are treated as
/// full-access sessions.
fn session_scope(ctx: Context, session_id: String) -> Result(String, Nil) {
  case
    sqlight.query(
      "SELECT scope FROM sessions WHERE id = ? LIMIT 1",
      ctx.db,
      [sqlight.text(session_id)],
      decode.at([0], decode.optional(decode.string)),
    )
  {
    Ok([Some(s)]) -> Ok(s)
    Ok([None]) -> Ok(scope_access)
    _ -> Error(Nil)
  }
}
