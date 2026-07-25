/// Per-node, in-memory rate limiting for abuse-prone endpoints.
///
/// Counters live in an ETS table (see `gleam_pds_ratelimit_ffi.erl`) keyed by a
/// rule bucket plus a subject: the client IP for unauthenticated endpoints, a
/// fingerprint of the bearer token for authenticated writes. Windows are fixed
/// (not sliding), which is coarse but cheap and good enough for spam control.
///
/// Limits reset when the node restarts and are not shared between machines.
/// Set GLEAM_PDS_RATELIMIT_DISABLED=true to turn enforcement off entirely.

import gleam_pds/context.{type Context}
import gleam_pds/crypto
import gleam_pds/web/response
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import wisp.{type Request, type Response}

/// One rule: at most `limit` hits per `window_seconds` per subject.
pub type Limit {
  Limit(bucket: String, limit: Int, window_seconds: Int)
}

pub type Decision {
  Allowed
  Limited(retry_after: Int)
}

@external(erlang, "gleam_pds_ratelimit_ffi", "init")
pub fn init() -> Nil

@external(erlang, "gleam_pds_ratelimit_ffi", "check")
fn ffi_check(
  bucket: String,
  key: String,
  limit: Int,
  window_seconds: Int,
) -> Decision

@external(erlang, "gleam_pds_ratelimit_ffi", "reset_all")
pub fn reset_all() -> Nil

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

/// Account creation, per client IP. Deliberately tight: a single person needs
/// a handful of accounts at most, a spammer needs hundreds.
pub fn create_account_limits() -> List(Limit) {
  [
    Limit("createAccount:10m", 3, 600),
    Limit("createAccount:day", 10, 86_400),
  ]
}

/// Login attempts, per client IP. Sized to allow a person fumbling their
/// password (and a client retrying a few sessions) while making credential
/// stuffing impractical.
pub fn create_session_limits() -> List(Limit) {
  [
    Limit("createSession:5m", 30, 300),
    Limit("createSession:day", 300, 86_400),
  ]
}

/// Repo writes (createRecord/putRecord/deleteRecord/applyWrites/uploadBlob),
/// per credential. Well above normal client behaviour, well below what a
/// runaway script does.
pub fn write_limits() -> List(Limit) {
  [
    Limit("write:min", 60, 60),
    Limit("write:hour", 1500, 3600),
  ]
}

/// Session refresh, per credential — cheap, but a broken client can hammer it.
pub fn refresh_limits() -> List(Limit) {
  [Limit("refresh:5m", 60, 300)]
}

// ---------------------------------------------------------------------------
// Enforcement
// ---------------------------------------------------------------------------

/// Run `next` unless `key` has exhausted any of `limits`, in which case
/// respond 429 with a Retry-After header. Call this BEFORE reading the request
/// body so a limited request costs as little as possible.
pub fn guard(
  ctx: Context,
  limits: List(Limit),
  key: String,
  next: fn() -> Response,
) -> Response {
  case check(ctx, limits, key) {
    Allowed -> next()
    Limited(retry_after) -> too_many_requests(retry_after)
  }
}

/// Evaluate every rule for a subject. All rules are counted even if an earlier
/// one already rejected, so a client cannot dodge the daily cap by tripping the
/// short-window one first.
pub fn check(ctx: Context, limits: List(Limit), key: String) -> Decision {
  case ctx.config.ratelimit_disabled {
    True -> Allowed
    False ->
      list.fold(limits, Allowed, fn(acc, l) {
        let decision = ffi_check(l.bucket, key, l.limit, l.window_seconds)
        case acc, decision {
          Limited(a), Limited(b) -> Limited(int.max(a, b))
          Limited(a), Allowed -> Limited(a)
          Allowed, d -> d
        }
      })
  }
}

fn too_many_requests(retry_after: Int) -> Response {
  response.xrpc_error(
    429,
    "RateLimitExceeded",
    "Rate limit exceeded. Try again in "
      <> int.to_string(retry_after)
      <> " seconds.",
  )
  |> wisp.set_header("retry-after", int.to_string(retry_after))
}

// ---------------------------------------------------------------------------
// Subjects
// ---------------------------------------------------------------------------

/// The client IP, as reported by the edge proxy.
///
/// `fly-client-ip` is set by Fly's proxy and cannot be forged by the client. A
/// client CAN prepend entries to `x-forwarded-for`, so we take the LAST entry —
/// the one the proxy appended. Falls back to a shared "unknown" bucket, which
/// intentionally errs on the strict side when we cannot identify the caller.
pub fn ip_key(req: Request) -> String {
  case client_ip(req) {
    Some(ip) -> "ip:" <> ip
    None -> "ip:unknown"
  }
}

/// Same IP detection as `ip_key`, without the rate-limit bucket prefix — for
/// callers that need the bare address, e.g. to pass on to Turnstile.
pub fn client_ip(req: Request) -> Option(String) {
  let from_fly =
    list.key_find(req.headers, "fly-client-ip")
    |> result.map(string.trim)
    |> result.try(fn(v) {
      case v {
        "" -> Error(Nil)
        _ -> Ok(v)
      }
    })

  case from_fly {
    Ok(ip) -> Some(ip)
    Error(_) ->
      case forwarded_for_last(req) {
        Ok(ip) -> Some(ip)
        Error(_) -> None
      }
  }
}

fn forwarded_for_last(req: Request) -> Result(String, Nil) {
  use header <- result.try(list.key_find(req.headers, "x-forwarded-for"))
  let parts =
    header
    |> string.split(",")
    |> list.map(string.trim)
    |> list.filter(fn(p) { p != "" })
  list.last(parts)
}

/// Identify an authenticated caller by a fingerprint of its bearer token, so
/// one account cannot multiply its write budget by rotating IPs. Falls back to
/// the IP when there is no token. The raw token is never stored: only a
/// truncated SHA-256, which is enough to tell credentials apart.
pub fn credential_key(req: Request) -> String {
  case bearer_token(req) {
    Ok(token) ->
      "tok:"
      <> string.slice(
        crypto.base64url_encode(crypto.sha256_string(token)),
        0,
        22,
      )
    Error(_) -> ip_key(req)
  }
}

fn bearer_token(req: Request) -> Result(String, Nil) {
  use auth <- result.try(list.key_find(req.headers, "authorization"))
  case string.starts_with(auth, "Bearer ") {
    True -> Ok(string.drop_start(auth, 7))
    False ->
      case string.starts_with(auth, "DPoP ") {
        True -> Ok(string.drop_start(auth, 5))
        False -> Error(Nil)
      }
  }
}
