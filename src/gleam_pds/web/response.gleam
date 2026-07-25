/// Shared HTTP response helpers for XRPC and other handlers.

import gleam/json
import wisp.{type Response}

/// Return a JSON error response in the standard XRPC error shape.
pub fn xrpc_error(status: Int, error: String, message: String) -> Response {
  let body =
    json.to_string(
      json.object([
        #("error", json.string(error)),
        #("message", json.string(message)),
      ]),
    )
  wisp.response(status)
  |> wisp.set_header("content-type", "application/json")
  |> wisp.set_body(wisp.Text(body))
}

/// Return a JSON success response.
pub fn json_response(status: Int, body: json.Json) -> Response {
  wisp.response(status)
  |> wisp.set_header("content-type", "application/json")
  |> wisp.set_body(wisp.Text(json.to_string(body)))
}

/// Return an HTML page wrapped in a minimal document shell.
pub fn html_page(status: Int, title: String, body_html: String) -> Response {
  let page =
    "<!DOCTYPE html>"
    <> "<html lang=\"en\">"
    <> "<head>"
    <> "<meta charset=\"utf-8\" />"
    <> "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />"
    <> "<title>"
    <> title
    <> "</title>"
    <> "<style>"
    <> "body{font-family:system-ui,sans-serif;max-width:600px;"
    <> "margin:2rem auto;padding:0 1rem;}"
    <> "input{display:block;margin:.5rem 0 1rem;padding:.5rem;"
    <> "width:100%;box-sizing:border-box;}"
    <> "button{padding:.5rem 1.5rem;cursor:pointer;}"
    <> "label{font-weight:600;}"
    <> "nav{margin-top:1rem;}"
    <> "a{color:#0066cc;}"
    <> "</style>"
    <> "</head>"
    <> "<body>"
    <> body_html
    <> "</body></html>"
  wisp.response(status)
  |> wisp.set_header("content-type", "text/html; charset=utf-8")
  |> wisp.set_body(wisp.Text(page))
}
