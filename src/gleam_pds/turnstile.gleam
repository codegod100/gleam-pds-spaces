/// Cloudflare Turnstile verification for account creation.
///
/// The widget's public sitekey renders in the browser; the secret stays
/// server-side and is posted straight to Cloudflare's siteverify endpoint
/// here. There is no intermediate Cloudflare Worker proxy — this backend can
/// already hold a secret safely (same pattern as GLEAM_PDS_SECRET), so a widget
/// answer is verified directly against Cloudflare from do_create_account.
import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/httpc
import gleam/io
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string

const siteverify_url = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

pub type VerifyError {
  /// Cloudflare reached but rejected the token (expired, reused, wrong
  /// sitekey, ...). Carries Cloudflare's own error codes for logging.
  Rejected(codes: List(String))
  /// Could not reach Cloudflare, or its response didn't parse.
  RequestFailed
}

/// Verify a Turnstile response token against Cloudflare. Returns `Ok(Nil)`
/// when Turnstile isn't configured on this server at all (it's an opt-in
/// layer, same as rate limiting and the signup gate) or when Cloudflare
/// confirms the token; `Error` otherwise.
pub fn verify(
  secret_key: Option(String),
  token: String,
  remote_ip: Option(String),
) -> Result(Nil, VerifyError) {
  case secret_key {
    None -> Ok(Nil)
    Some(secret) -> do_verify(secret, token, remote_ip)
  }
}

fn do_verify(
  secret: String,
  token: String,
  remote_ip: Option(String),
) -> Result(Nil, VerifyError) {
  let fields = [
    #("secret", json.string(secret)),
    #("response", json.string(token)),
  ]
  let fields = case remote_ip {
    Some(ip) -> list.append(fields, [#("remoteip", json.string(ip))])
    None -> fields
  }
  let body = json.to_string(json.object(fields))

  case request.to(siteverify_url) {
    Error(_) -> Error(RequestFailed)
    Ok(req) -> {
      let req =
        req
        |> request.set_method(http.Post)
        |> request.set_header("content-type", "application/json")
        |> request.set_body(body)

      case httpc.send(req) {
        Error(_) -> {
          io.println("[turnstile] Failed to contact siteverify")
          Error(RequestFailed)
        }
        Ok(resp) -> {
          let decoder = {
            use success <- decode.field("success", decode.bool)
            use codes <- decode.optional_field(
              "error-codes",
              [],
              decode.list(decode.string),
            )
            decode.success(#(success, codes))
          }
          case json.parse(resp.body, decoder) {
            Ok(#(True, _)) -> Ok(Nil)
            Ok(#(False, codes)) -> {
              io.println(
                "[turnstile] Rejected: " <> string.join(codes, ", "),
              )
              Error(Rejected(codes))
            }
            Error(_) -> {
              io.println("[turnstile] Unparseable siteverify response")
              Error(RequestFailed)
            }
          }
        }
      }
    }
  }
}

