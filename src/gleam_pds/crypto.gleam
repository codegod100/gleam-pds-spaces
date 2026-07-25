/// Crypto utilities: JWT, key generation, hashing, CID computation
/// Uses Erlang :crypto and :public_key FFI

import gleam/bit_array
import gleam/crypto
import gleam/dynamic/decode
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string

// ---- Base64 URL encoding ----

@external(erlang, "gleam_pds_crypto_ffi", "base64url_encode")
pub fn base64url_encode(data: BitArray) -> String

@external(erlang, "gleam_pds_crypto_ffi", "base64url_decode")
pub fn base64url_decode(data: String) -> Result(BitArray, Nil)

// ---- Key generation ----

pub type KeyPair {
  KeyPair(private_key: BitArray, public_key: BitArray)
}

@external(erlang, "gleam_pds_crypto_ffi", "generate_p256_keypair")
pub fn generate_p256_keypair() -> KeyPair

/// Derive the (uncompressed) P-256 public key for a raw private scalar. Used
/// for the server rotation key, which is configured as a private key only.
@external(erlang, "gleam_pds_crypto_ffi", "p256_public_from_private")
pub fn p256_public_from_private(private_key: BitArray) -> BitArray

@external(erlang, "gleam_pds_crypto_ffi", "sign_es256")
pub fn sign_es256(data: BitArray, private_key: BitArray) -> BitArray

@external(erlang, "gleam_pds_crypto_ffi", "verify_es256")
pub fn verify_es256(
  data: BitArray,
  signature: BitArray,
  public_key: BitArray,
) -> Bool

// ---- SHA-256 ----

pub fn sha256(data: BitArray) -> BitArray {
  crypto.hash(crypto.Sha256, data)
}

pub fn sha256_string(data: String) -> BitArray {
  sha256(bit_array.from_string(data))
}

/// Constant-time comparison of two byte arrays. Delegates to gleam/crypto so
/// callers importing gleam_pds/crypto can compare secrets without a timing leak.
pub fn secure_compare(a: BitArray, b: BitArray) -> Bool {
  crypto.secure_compare(a, b)
}

// ---- CID computation (CIDv1 with dag-cbor codec + sha256) ----

pub fn compute_cid(data: BitArray) -> String {
  let hash = sha256(data)
  // CIDv1: version(1) + codec(dag-cbor=0x71) + multihash(sha256=0x12, len=32, digest)
  let cid_bytes =
    bit_array.concat([
      <<1, 0x71, 0x12, 32>>,
      hash,
    ])
  // base32lower encoding with 'b' prefix (CIDv1 base32lower)
  "b" <> string.lowercase(base32_encode(cid_bytes))
}

/// CID for a raw blob (CIDv1, raw codec 0x55 + sha256). AT Protocol blob refs
/// MUST use the raw codec (bafkrei… CIDs), NOT dag-cbor, or the appview/CDN
/// rejects the blob when it re-derives and validates the CID.
pub fn compute_blob_cid(data: BitArray) -> String {
  let hash = sha256(data)
  let cid_bytes =
    bit_array.concat([
      <<1, 0x55, 0x12, 32>>,
      hash,
    ])
  "b" <> string.lowercase(base32_encode(cid_bytes))
}

@external(erlang, "gleam_pds_crypto_ffi", "base32_encode")
pub fn base32_encode(data: BitArray) -> String

@external(erlang, "gleam_pds_crypto_ffi", "base32_decode")
pub fn base32_decode(data: String) -> Result(BitArray, Nil)

// ---- JWT ----

pub fn create_jwt(
  claims: List(#(String, json.Json)),
  secret: String,
) -> String {
  let header =
    json.to_string(json.object([
      #("alg", json.string("HS256")),
      #("typ", json.string("JWT")),
    ]))

  let payload = json.to_string(json.object(claims))

  let header_b64 = base64url_encode(bit_array.from_string(header))
  let payload_b64 = base64url_encode(bit_array.from_string(payload))

  let signing_input = header_b64 <> "." <> payload_b64
  let signature =
    crypto.hmac(
      bit_array.from_string(signing_input),
      crypto.Sha256,
      bit_array.from_string(secret),
    )
  let signature_b64 = base64url_encode(signature)

  signing_input <> "." <> signature_b64
}

/// Decoded, verified JWT claims. Only the fields we care about are surfaced.
pub type Claims {
  Claims(
    sub: Option(String),
    scope: Option(String),
    client_id: Option(String),
    aud: Option(String),
    jti: Option(String),
    iat: Option(Int),
    exp: Option(Int),
    cnf_jkt: Option(String),
  )
}

pub type JwtError {
  InvalidFormat
  InvalidSignature
  InvalidPayload
  ExpiredToken
}

fn claims_decoder() -> decode.Decoder(Claims) {
  use sub <- decode.optional_field(
    "sub",
    None,
    decode.optional(decode.string),
  )
  use scope <- decode.optional_field(
    "scope",
    None,
    decode.optional(decode.string),
  )
  use client_id <- decode.optional_field(
    "client_id",
    None,
    decode.optional(decode.string),
  )
  use aud <- decode.optional_field(
    "aud",
    None,
    decode.optional(decode.string),
  )
  use jti <- decode.optional_field(
    "jti",
    None,
    decode.optional(decode.string),
  )
  use iat <- decode.optional_field("iat", None, decode.optional(decode.int))
  use exp <- decode.optional_field("exp", None, decode.optional(decode.int))
  use cnf_jkt <- decode.optional_field("cnf", None, {
    use jkt <- decode.optional_field(
      "jkt",
      None,
      decode.optional(decode.string),
    )
    decode.success(jkt)
  })
  decode.success(Claims(
    sub: sub,
    scope: scope,
    client_id: client_id,
    aud: aud,
    jti: jti,
    iat: iat,
    exp: exp,
    cnf_jkt: cnf_jkt,
  ))
}

/// Verify an HS256 JWT: constant-time signature check, JSON-decode the payload,
/// and enforce `exp`. Returns the decoded claims so callers can inspect
/// scope/sub/aud/cnf. Distinguishes an expired token from other failures.
pub fn verify_jwt(token: String, secret: String) -> Result(Claims, JwtError) {
  case string.split(token, ".") {
    [header_b64, payload_b64, signature_b64] -> {
      let signing_input = header_b64 <> "." <> payload_b64
      let expected_sig =
        crypto.hmac(
          bit_array.from_string(signing_input),
          crypto.Sha256,
          bit_array.from_string(secret),
        )
      case base64url_decode(signature_b64) {
        Ok(sig) ->
          case crypto.secure_compare(sig, expected_sig) {
            True -> {
              use payload_bytes <- result.try(result.replace_error(
                base64url_decode(payload_b64),
                InvalidPayload,
              ))
              use payload_str <- result.try(result.replace_error(
                bit_array.to_string(payload_bytes),
                InvalidPayload,
              ))
              use claims <- result.try(result.replace_error(
                json.parse(payload_str, claims_decoder()),
                InvalidPayload,
              ))
              // Enforce expiry. Tokens we issue always carry `exp`; a token
              // with no exp is treated as invalid rather than immortal.
              case claims.exp {
                None -> Error(InvalidPayload)
                Some(exp) -> {
                  let now = timestamp_microseconds() / 1_000_000
                  case now >= exp {
                    True -> Error(ExpiredToken)
                    False -> Ok(claims)
                  }
                }
              }
            }
            False -> Error(InvalidSignature)
          }
        Error(_) -> Error(InvalidSignature)
      }
    }
    _ -> Error(InvalidFormat)
  }
}

// ---- DPoP proof validation (RFC 9449) ----

pub type DpopError {
  DpopInvalidFormat
  DpopBadSignature
  DpopBadHtm
  DpopBadHtu
  DpopReplay
  DpopStale
  DpopBadAth
  /// The proof carried no `nonce` claim, or one we did not issue. Callers must
  /// answer with `use_dpop_nonce` and a fresh `DPoP-Nonce` header so the
  /// client can retry (RFC 9449 §8).
  DpopBadNonce
}

@external(erlang, "gleam_pds_crypto_ffi", "verify_dpop_es256")
fn verify_dpop_es256(
  signing_input: String,
  raw_sig: BitArray,
  x: String,
  y: String,
) -> Bool

@external(erlang, "gleam_pds_crypto_ffi", "jwk_thumbprint")
fn jwk_thumbprint(x: String, y: String) -> String

@external(erlang, "gleam_pds_crypto_ffi", "dpop_jti_seen")
fn dpop_jti_seen(jti: String, ttl_seconds: Int) -> Bool

fn dpop_header_decoder() -> decode.Decoder(#(String, String, String, String, String, String)) {
  use typ <- decode.field("typ", decode.string)
  use alg <- decode.field("alg", decode.string)
  use jwk <- decode.field("jwk", {
    use kty <- decode.field("kty", decode.string)
    use crv <- decode.field("crv", decode.string)
    use x <- decode.field("x", decode.string)
    use y <- decode.field("y", decode.string)
    decode.success(#(kty, crv, x, y))
  })
  let #(kty, crv, x, y) = jwk
  decode.success(#(typ, alg, kty, crv, x, y))
}

fn dpop_payload_decoder() -> decode.Decoder(
  #(String, String, Int, String, Option(String), Option(String)),
) {
  use htm <- decode.field("htm", decode.string)
  use htu <- decode.field("htu", decode.string)
  use iat <- decode.field("iat", decode.int)
  use jti <- decode.field("jti", decode.string)
  use ath <- decode.optional_field(
    "ath",
    None,
    decode.optional(decode.string),
  )
  use nonce <- decode.optional_field(
    "nonce",
    None,
    decode.optional(decode.string),
  )
  decode.success(#(htm, htu, iat, jti, ath, nonce))
}

/// Validate a DPoP proof JWT. On success returns the JWK SHA-256 thumbprint
/// (RFC 7638), i.e. the value bound into `cnf.jkt`.
///
/// - `method` / `htu`: the expected HTTP method and full request URI.
/// - `expected_ath`: `Some(access_token)` on resource access (proof must carry
///   a matching `ath`); `None` at the token endpoint.
/// - `valid_nonces`: server-issued nonces currently accepted. Pass `[]` to
///   skip the nonce check; otherwise the proof must carry one of these values
///   in its `nonce` claim or `DpopBadNonce` is returned.
pub fn verify_dpop(
  proof: String,
  method: String,
  htu: String,
  expected_ath: Option(String),
  valid_nonces: List(String),
) -> Result(String, DpopError) {
  case string.split(proof, ".") {
    [h_b64, p_b64, s_b64] -> {
      let signing_input = h_b64 <> "." <> p_b64
      use header_bytes <- result.try(result.replace_error(
        base64url_decode(h_b64),
        DpopInvalidFormat,
      ))
      use header_str <- result.try(result.replace_error(
        bit_array.to_string(header_bytes),
        DpopInvalidFormat,
      ))
      use #(typ, alg, kty, crv, x, y) <- result.try(result.replace_error(
        json.parse(header_str, dpop_header_decoder()),
        DpopInvalidFormat,
      ))
      case typ == "dpop+jwt" && alg == "ES256" && kty == "EC" && crv == "P-256" {
        False -> Error(DpopInvalidFormat)
        True -> {
          use payload_bytes <- result.try(result.replace_error(
            base64url_decode(p_b64),
            DpopInvalidFormat,
          ))
          use payload_str <- result.try(result.replace_error(
            bit_array.to_string(payload_bytes),
            DpopInvalidFormat,
          ))
          use #(htm, p_htu, iat, jti, ath, nonce) <- result.try(
            result.replace_error(
              json.parse(payload_str, dpop_payload_decoder()),
              DpopInvalidFormat,
            ),
          )
          use raw_sig <- result.try(result.replace_error(
            base64url_decode(s_b64),
            DpopInvalidFormat,
          ))
          case verify_dpop_es256(signing_input, raw_sig, x, y) {
            False -> Error(DpopBadSignature)
            True ->
              case string.uppercase(htm) == string.uppercase(method) {
                False -> Error(DpopBadHtm)
                True ->
                  case p_htu == htu {
                    False -> Error(DpopBadHtu)
                    True -> {
                      let now = timestamp_microseconds() / 1_000_000
                      case iat > now + 30 || iat < now - 300 {
                        True -> Error(DpopStale)
                        False ->
                          case dpop_jti_seen(jti, 300) {
                            True -> Error(DpopReplay)
                            False ->
                              case check_ath(expected_ath, ath) {
                                False -> Error(DpopBadAth)
                                True ->
                                  case check_nonce(valid_nonces, nonce) {
                                    False -> Error(DpopBadNonce)
                                    True -> Ok(jwk_thumbprint(x, y))
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
    }
    _ -> Error(DpopInvalidFormat)
  }
}

fn check_ath(expected_ath: Option(String), ath: Option(String)) -> Bool {
  case expected_ath {
    None -> True
    Some(token) -> {
      let want = base64url_encode(sha256_string(token))
      case ath {
        Some(a) -> a == want
        None -> False
      }
    }
  }
}

fn check_nonce(valid_nonces: List(String), nonce: Option(String)) -> Bool {
  case valid_nonces {
    [] -> True
    _ ->
      case nonce {
        Some(n) -> list.contains(valid_nonces, n)
        None -> False
      }
  }
}

// ---- DPoP server nonce (RFC 9449 §8) ----
//
// Nonces are stateless: HMAC(secret, window counter) where the window rolls
// every 5 minutes. We accept the current and previous window, so an issued
// nonce stays valid for 5–10 minutes and nothing needs storing or sweeping.

const dpop_nonce_window_seconds = 300

fn dpop_nonce_for_window(secret: String, window: Int) -> String {
  crypto.hmac(
    bit_array.from_string("dpop-nonce:" <> int.to_string(window)),
    crypto.Sha256,
    bit_array.from_string(secret),
  )
  |> base64url_encode
}

/// The nonce clients should use next, sent in every `DPoP-Nonce` header.
pub fn dpop_nonce(secret: String) -> String {
  let window =
    timestamp_microseconds() / 1_000_000 / dpop_nonce_window_seconds
  dpop_nonce_for_window(secret, window)
}

/// All nonces currently accepted in proofs: the active window and the one
/// before it, so a client is never invalidated mid-request by a window roll.
pub fn dpop_nonces_accepted(secret: String) -> List(String) {
  let window =
    timestamp_microseconds() / 1_000_000 / dpop_nonce_window_seconds
  [
    dpop_nonce_for_window(secret, window),
    dpop_nonce_for_window(secret, window - 1),
  ]
}

// ---- Random ----

pub fn random_string(length: Int) -> String {
  crypto.strong_random_bytes(length)
  |> base64url_encode
  |> string.slice(0, length)
}

// ---- TID generation (AT Protocol Timestamp ID) ----

@external(erlang, "gleam_pds_crypto_ffi", "timestamp_microseconds")
pub fn timestamp_microseconds() -> Int

@external(erlang, "gleam_pds_crypto_ffi", "generate_tid")
pub fn generate_tid() -> String

// ---- Password hashing (bcrypt-like using PBKDF2) ----

pub fn hash_password(password: String) -> String {
  let salt = crypto.strong_random_bytes(16)
  let salt_b64 = base64url_encode(salt)
  let hash = pbkdf2(password, salt, 100_000)
  let hash_b64 = base64url_encode(hash)
  salt_b64 <> ":" <> hash_b64
}

pub fn verify_password(password: String, stored: String) -> Bool {
  case string.split(stored, ":") {
    [salt_b64, hash_b64] -> {
      case base64url_decode(salt_b64), base64url_decode(hash_b64) {
        Ok(salt), Ok(expected_hash) -> {
          let computed = pbkdf2(password, salt, 100_000)
          crypto.secure_compare(computed, expected_hash)
        }
        _, _ -> False
      }
    }
    _ -> False
  }
}

@external(erlang, "gleam_pds_crypto_ffi", "pbkdf2")
fn pbkdf2(password: String, salt: BitArray, iterations: Int) -> BitArray
