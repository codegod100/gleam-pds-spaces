import envoy
import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string

pub type Config {
  Config(
    hostname: String,
    handle_domain: String,
    port: Int,
    public_url: String,
    db_path: String,
    secret_key: String,
    signups_disabled: Bool,
    ratelimit_disabled: Bool,
    turnstile_site_key: Option(String),
    turnstile_secret_key: Option(String),
    rotation_key: Option(BitArray),
    /// PDS admin password for `admin:<password>` Basic auth on
    /// `com.atproto.admin.*` and `com.atproto.server.createInviteCode`.
    /// Unset disables the admin API (endpoints return 401).
    admin_password: Option(String),
  )
}

pub fn load() -> Config {
  let hostname =
    envoy.get("GLEAM_PDS_HOSTNAME")
    |> result.unwrap("gleam-pds.exe.xyz")

  let handle_domain =
    envoy.get("GLEAM_PDS_HANDLE_DOMAIN")
    |> result.unwrap(hostname)

  let port =
    envoy.get("GLEAM_PDS_PORT")
    |> result.try(int.parse)
    |> result.unwrap(8000)

  let public_url =
    envoy.get("GLEAM_PDS_PUBLIC_URL")
    |> result.unwrap("https://" <> hostname)

  let db_path =
    envoy.get("GLEAM_PDS_DB_PATH")
    |> result.unwrap("gleam_pds.db")

  // C1: never silently fall back to a hardcoded/default secret. A weak or
  // missing signing secret allows anyone to forge session/OAuth JWTs, so we
  // fail loudly at startup instead of booting with a known-insecure key.
  let secret_key = case envoy.get("GLEAM_PDS_SECRET") {
    Ok(s) ->
      case is_weak_secret(s) {
        True ->
          panic as "GLEAM_PDS_SECRET is set to a weak, short, or well-known default value. Refusing to start. Provide a strong (>= 16 char) random secret via the environment (EnvironmentFile or systemd credential)."
        False -> s
      }
    Error(_) ->
      panic as "GLEAM_PDS_SECRET environment variable is required but was not set. Refusing to start with a default secret. Provide a strong random secret via the environment."
  }

  // Gate new account creation. Set GLEAM_PDS_SIGNUPS_DISABLED=true (or 1/yes) to
  // reject com.atproto.server.createAccount. Defaults to enabled.
  let signups_disabled = env_flag("GLEAM_PDS_SIGNUPS_DISABLED")

  // Escape hatch for local development / load testing. Rate limiting is on by
  // default; set GLEAM_PDS_RATELIMIT_DISABLED=true to bypass it.
  let ratelimit_disabled = env_flag("GLEAM_PDS_RATELIMIT_DISABLED")

  // Cloudflare Turnstile on the registration form. Opt-in: unset means no
  // widget renders and createAccount skips verification, same as the
  // signups/rate-limit toggles above. The site key is public (ships to the
  // browser); the secret key never leaves this process — it is posted
  // directly to Cloudflare's siteverify endpoint from do_create_account.
  let turnstile_site_key = case envoy.get("GLEAM_PDS_TURNSTILE_SITE_KEY") {
    Ok(k) if k != "" -> Some(k)
    _ -> None
  }
  let turnstile_secret_key = case envoy.get("GLEAM_PDS_TURNSTILE_SECRET_KEY") {
    Ok(k) if k != "" -> Some(k)
    _ -> None
  }

  // Dedicated server-level PLC rotation key (hex-encoded 32-byte P-256
  // private key, e.g. from `openssl rand -hex 32`). When set, new did:plc
  // identities list ONLY this key in rotationKeys, so a compromised account
  // signing key cannot rewrite the DID. Optional: unset keeps the legacy
  // behaviour of reusing the account signing key. A set-but-malformed value
  // is a fatal misconfiguration, not something to silently ignore.
  let rotation_key = case envoy.get("GLEAM_PDS_ROTATION_KEY") {
    Ok(hex) if hex != "" ->
      case bit_array.base16_decode(hex) {
        Ok(key) ->
          case bit_array.byte_size(key) == 32 {
            True -> Some(key)
            False ->
              panic as "GLEAM_PDS_ROTATION_KEY must be exactly 32 bytes (64 hex characters). Refusing to start with a malformed rotation key."
          }
        Error(_) ->
          panic as "GLEAM_PDS_ROTATION_KEY is not valid hex. Provide a 32-byte P-256 private key as 64 hex characters (e.g. `openssl rand -hex 32`)."
      }
    _ -> None
  }

  let admin_password = case envoy.get("GLEAM_PDS_ADMIN_PASSWORD") {
    Ok(p) if p != "" -> Some(p)
    _ -> None
  }

  Config(
    hostname: hostname,
    handle_domain: handle_domain,
    port: port,
    public_url: public_url,
    db_path: db_path,
    secret_key: secret_key,
    signups_disabled: signups_disabled,
    ratelimit_disabled: ratelimit_disabled,
    turnstile_site_key: turnstile_site_key,
    turnstile_secret_key: turnstile_secret_key,
    rotation_key: rotation_key,
    admin_password: admin_password,
  )
}

/// Read a boolean environment flag. Absent or unrecognised means False.
fn env_flag(name: String) -> Bool {
  case envoy.get(name) {
    Ok(v) ->
      case string.lowercase(string.trim(v)) {
        "true" | "1" | "yes" | "on" -> True
        _ -> False
      }
    Error(_) -> False
  }
}

/// Reject secrets that are empty, too short, or a known-weak/default value.
fn is_weak_secret(s: String) -> Bool {
  let known_weak = [
    "gleam-pds-dev-secret-change-me-in-production",
    "gleam-pds-production-secret-key",
    "changeme",
    "change-me",
    "secret",
    "password",
    "",
  ]
  string.length(s) < 16 || list.contains(known_weak, s)
}
