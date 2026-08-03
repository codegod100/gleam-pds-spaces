/// XRPC com.atproto.space.* handlers — scaffold stubs only.
///
/// Auth is required (via `server.get_auth_did`); unauthenticated calls get
/// the same 401 AuthenticationRequired shape as the rest of gleam-pds.
/// List endpoints return empty collections; mutating / sync endpoints return
/// MethodNotImplemented until a real spaces implementation lands.

import gleam_pds/context.{type Context}
import gleam_pds/web/response
import gleam_pds/xrpc/server
import gleam/json
import wisp.{type Request, type Response}

fn not_implemented(method: String) -> Response {
  response.xrpc_error(
    400,
    "MethodNotImplemented",
    "Space method not implemented: " <> method,
  )
}

fn require(req: Request, ctx: Context, next: fn(String) -> Response) -> Response {
  case server.get_auth_did(req, ctx) {
    Error(resp) -> resp
    Ok(did) -> next(did)
  }
}

pub fn list_spaces(req: Request, ctx: Context) -> Response {
  use _did <- require(req, ctx)
  response.json_response(
    200,
    json.object([#("spaces", json.preprocessed_array([]))]),
  )
}

pub fn get_space(req: Request, ctx: Context) -> Response {
  use _did <- require(req, ctx)
  not_implemented("com.atproto.space.getSpace")
}

pub fn get_space_credential(req: Request, ctx: Context) -> Response {
  use _did <- require(req, ctx)
  not_implemented("com.atproto.space.getSpaceCredential")
}

pub fn notify_space_deleted(req: Request, ctx: Context) -> Response {
  use _did <- require(req, ctx)
  not_implemented("com.atproto.space.notifySpaceDeleted")
}

pub fn apply_writes(req: Request, ctx: Context) -> Response {
  use _did <- require(req, ctx)
  not_implemented("com.atproto.space.applyWrites")
}

pub fn create_record(req: Request, ctx: Context) -> Response {
  use _did <- require(req, ctx)
  not_implemented("com.atproto.space.createRecord")
}

pub fn put_record(req: Request, ctx: Context) -> Response {
  use _did <- require(req, ctx)
  not_implemented("com.atproto.space.putRecord")
}

pub fn delete_record(req: Request, ctx: Context) -> Response {
  use _did <- require(req, ctx)
  not_implemented("com.atproto.space.deleteRecord")
}

pub fn get_record(req: Request, ctx: Context) -> Response {
  use _did <- require(req, ctx)
  not_implemented("com.atproto.space.getRecord")
}

pub fn list_records(req: Request, ctx: Context) -> Response {
  use _did <- require(req, ctx)
  response.json_response(
    200,
    json.object([#("records", json.preprocessed_array([]))]),
  )
}

pub fn get_repo(req: Request, ctx: Context) -> Response {
  use _did <- require(req, ctx)
  not_implemented("com.atproto.space.getRepo")
}

pub fn get_latest_commit(req: Request, ctx: Context) -> Response {
  use _did <- require(req, ctx)
  not_implemented("com.atproto.space.getLatestCommit")
}

pub fn list_repos(req: Request, ctx: Context) -> Response {
  use _did <- require(req, ctx)
  response.json_response(
    200,
    json.object([#("repos", json.preprocessed_array([]))]),
  )
}

pub fn list_repo_ops(req: Request, ctx: Context) -> Response {
  use _did <- require(req, ctx)
  response.json_response(
    200,
    json.object([#("ops", json.preprocessed_array([]))]),
  )
}

pub fn get_blob(req: Request, ctx: Context) -> Response {
  use _did <- require(req, ctx)
  not_implemented("com.atproto.space.getBlob")
}

pub fn get_delegation_token(req: Request, ctx: Context) -> Response {
  use _did <- require(req, ctx)
  not_implemented("com.atproto.space.getDelegationToken")
}

pub fn notify_write(req: Request, ctx: Context) -> Response {
  use _did <- require(req, ctx)
  not_implemented("com.atproto.space.notifyWrite")
}

pub fn register_notify(req: Request, ctx: Context) -> Response {
  use _did <- require(req, ctx)
  not_implemented("com.atproto.space.registerNotify")
}
