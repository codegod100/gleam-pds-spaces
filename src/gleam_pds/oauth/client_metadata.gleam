/// atproto OAuth client identity: the client_id IS an HTTPS URL pointing at
/// the client's metadata document (client-id-metadata-document). We fetch it
/// at PAR time and refuse authorization requests whose parameters the client
/// never declared, so a stolen redirect can't be bolted onto someone else's
/// client_id.
///
/// The one exception, per the spec, is loopback development clients
/// (`http://localhost`), whose metadata is implied rather than fetched.

import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/httpc
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string

pub type ClientMetadata {
  ClientMetadata(
    client_id: String,
    redirect_uris: List(String),
    grant_types: List(String),
    response_types: List(String),
    scope: Option(String),
    dpop_bound_access_tokens: Bool,
  )
}

/// Validate an authorization request against the client's published metadata.
/// `scope` is the space-separated scope string the client is requesting.
pub fn validate(
  client_id: String,
  redirect_uri: String,
  scope: String,
) -> Result(Nil, String) {
  case is_loopback_client(client_id) {
    True -> validate_loopback_redirect(redirect_uri)
    False -> {
      use _ <- result.try(check_client_id_url(client_id))
      use meta <- result.try(fetch(client_id))
      check_against_metadata(meta, client_id, redirect_uri, scope)
    }
  }
}

/// Loopback development clients: exactly `http://localhost` (optionally with
/// a query string carrying redirect_uri/scope), never any other http URL.
fn is_loopback_client(client_id: String) -> Bool {
  client_id == "http://localhost"
  || string.starts_with(client_id, "http://localhost?")
  || string.starts_with(client_id, "http://localhost/?")
}

fn validate_loopback_redirect(redirect_uri: String) -> Result(Nil, String) {
  case
    string.starts_with(redirect_uri, "http://127.0.0.1")
    || string.starts_with(redirect_uri, "http://[::1]")
  {
    True -> Ok(Nil)
    False ->
      Error(
        "Loopback clients must redirect to http://127.0.0.1 or http://[::1]",
      )
  }
}

fn check_client_id_url(client_id: String) -> Result(Nil, String) {
  case
    string.starts_with(client_id, "https://")
    && !string.contains(client_id, "#")
  {
    True -> Ok(Nil)
    False ->
      Error("client_id must be an https:// URL with no fragment")
  }
}

fn check_against_metadata(
  meta: ClientMetadata,
  client_id: String,
  redirect_uri: String,
  scope: String,
) -> Result(Nil, String) {
  use _ <- result.try(case meta.client_id == client_id {
    True -> Ok(Nil)
    False ->
      Error("client_id in metadata document does not match the request")
  })
  use _ <- result.try(case list.contains(meta.redirect_uris, redirect_uri) {
    True -> Ok(Nil)
    False -> Error("redirect_uri is not registered in the client metadata")
  })
  use _ <- result.try(case
    list.contains(meta.grant_types, "authorization_code")
  {
    True -> Ok(Nil)
    False -> Error("Client does not declare the authorization_code grant")
  })
  use _ <- result.try(case list.contains(meta.response_types, "code") {
    True -> Ok(Nil)
    False -> Error("Client does not declare the code response type")
  })
  use _ <- result.try(case meta.dpop_bound_access_tokens {
    True -> Ok(Nil)
    False ->
      Error("atproto clients must set dpop_bound_access_tokens to true")
  })
  check_scope(meta, scope)
}

/// Every requested scope value must appear in the client's declared scope.
/// A metadata document with no scope field is treated as declaring only
/// `atproto`.
fn check_scope(meta: ClientMetadata, requested: String) -> Result(Nil, String) {
  let declared =
    case meta.scope {
      Some(s) -> s
      None -> "atproto"
    }
    |> string.split(" ")
  let undeclared =
    string.split(requested, " ")
    |> list.filter(fn(s) { s != "" && !list.contains(declared, s) })
  case undeclared {
    [] -> Ok(Nil)
    [first, ..] -> Error("Requested scope not declared by client: " <> first)
  }
}

fn fetch(client_id: String) -> Result(ClientMetadata, String) {
  case request.to(client_id) {
    Error(_) -> Error("client_id is not a fetchable URL")
    Ok(req0) -> {
      let req =
        req0
        |> request.set_method(http.Get)
        |> request.set_header("accept", "application/json")
      case httpc.send(req) {
        Error(_) -> Error("Failed to fetch client metadata document")
        Ok(resp) ->
          case resp.status {
            200 ->
              case json.parse(resp.body, metadata_decoder()) {
                Ok(meta) -> Ok(meta)
                Error(_) ->
                  Error("Client metadata document is not valid JSON metadata")
              }
            status ->
              Error(
                "Client metadata fetch returned HTTP "
                <> int.to_string(status),
              )
          }
      }
    }
  }
}

fn metadata_decoder() -> decode.Decoder(ClientMetadata) {
  use client_id <- decode.field("client_id", decode.string)
  use redirect_uris <- decode.field(
    "redirect_uris",
    decode.list(decode.string),
  )
  use grant_types <- decode.optional_field(
    "grant_types",
    ["authorization_code"],
    decode.list(decode.string),
  )
  use response_types <- decode.optional_field(
    "response_types",
    ["code"],
    decode.list(decode.string),
  )
  use scope <- decode.optional_field(
    "scope",
    None,
    decode.optional(decode.string),
  )
  use dpop_bound_access_tokens <- decode.optional_field(
    "dpop_bound_access_tokens",
    False,
    decode.bool,
  )
  decode.success(ClientMetadata(
    client_id: client_id,
    redirect_uris: redirect_uris,
    grant_types: grant_types,
    response_types: response_types,
    scope: scope,
    dpop_bound_access_tokens: dpop_bound_access_tokens,
  ))
}
