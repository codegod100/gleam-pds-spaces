/// XRPC com.atproto.simplespace.* handlers — scaffold stubs only.
///
/// Auth is required (via `server.get_auth_did`); unauthenticated calls get
/// the same 401 AuthenticationRequired shape as the rest of gleam-pds.
/// List endpoints return empty collections; mutating endpoints return
/// MethodNotImplemented until a real simplespace host lands.

import gleam_pds/context.{type Context}
import gleam_pds/web/response
import gleam_pds/xrpc/server
import gleam/json
import wisp.{type Request, type Response}

fn not_implemented(method: String) -> Response {
  response.xrpc_error(
    400,
    "MethodNotImplemented",
    "Simplespace method not implemented: " <> method,
  )
}

fn require(req: Request, ctx: Context, next: fn(String) -> Response) -> Response {
  case server.get_auth_did(req, ctx) {
    Error(resp) -> resp
    Ok(did) -> next(did)
  }
}

pub fn create_space(req: Request, ctx: Context) -> Response {
  use _did <- require(req, ctx)
  not_implemented("com.atproto.simplespace.createSpace")
}

pub fn update_space(req: Request, ctx: Context) -> Response {
  use _did <- require(req, ctx)
  not_implemented("com.atproto.simplespace.updateSpace")
}

pub fn delete_space(req: Request, ctx: Context) -> Response {
  use _did <- require(req, ctx)
  not_implemented("com.atproto.simplespace.deleteSpace")
}

pub fn add_member(req: Request, ctx: Context) -> Response {
  use _did <- require(req, ctx)
  not_implemented("com.atproto.simplespace.addMember")
}

pub fn remove_member(req: Request, ctx: Context) -> Response {
  use _did <- require(req, ctx)
  not_implemented("com.atproto.simplespace.removeMember")
}

pub fn list_members(req: Request, ctx: Context) -> Response {
  use _did <- require(req, ctx)
  response.json_response(
    200,
    json.object([#("members", json.preprocessed_array([]))]),
  )
}

pub fn check_user_access(req: Request, ctx: Context) -> Response {
  use _did <- require(req, ctx)
  response.json_response(
    200,
    json.object([#("authorized", json.bool(False))]),
  )
}
