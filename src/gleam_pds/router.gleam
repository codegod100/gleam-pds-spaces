import gleam_pds/context.{type Context}
import gleam_pds/did
import gleam_pds/oauth/oauth_handler
import gleam_pds/passkey/passkey_handler
import gleam_pds/ratelimit
import gleam_pds/web/pages
import gleam_pds/web/response
import gleam_pds/xrpc/account
import gleam_pds/xrpc/identity
import gleam_pds/xrpc/proxy
import gleam_pds/xrpc/repo
import gleam_pds/xrpc/server
import gleam_pds/xrpc/simplespace
import gleam_pds/xrpc/space
import gleam_pds/xrpc/sync
import gleam/dynamic/decode
import gleam/http.{Get, Options, Post}
import gleam/json
import gleam/list
import gleam/result
import gleam/string
import sqlight
import wisp.{type Request, type Response}

pub fn handle_request(req: Request, ctx: Context) -> Response {
  let req = wisp.method_override(req)
  use <- wisp.log_request(req)
  use <- cors_middleware(req)
  use <- wisp.rescue_crashes
  // Static assets (logo, OG image) live in the app's priv/static directory,
  // which `gleam export erlang-shipment` bundles into the release.
  use <- wisp.serve_static(req, under: "/static", from: static_directory())

  case wisp.path_segments(req) {
    ["xrpc", "_health"] -> handle_health()
    ["xrpc", method] -> handle_xrpc(req, ctx, method)
    [".well-known", "atproto-did"] -> handle_atproto_did(req, ctx)
    [".well-known", "did.json"] -> handle_did_json(req, ctx)
    [".well-known", "oauth-authorization-server"] ->
      oauth_handler.metadata(req, ctx)
    [".well-known", "oauth-protected-resource"] ->
      oauth_handler.protected_resource(req, ctx)
    ["oauth", "authorize"] -> oauth_handler.authorize(req, ctx)
    // Token exchange is an unauthenticated credential path: same per-IP
    // budget as password login.
    ["oauth", "token"] ->
      ratelimit.guard(
        ctx,
        ratelimit.create_session_limits(),
        ratelimit.ip_key(req),
        fn() { oauth_handler.token(req, ctx) },
      )
    ["oauth", "par"] -> oauth_handler.par(req, ctx)
    ["oauth", "jwks"] -> oauth_handler.jwks(req, ctx)
    ["oauth", "client-metadata.json"] -> oauth_handler.client_metadata(req, ctx)
    ["api", "passkey", ..rest] -> passkey_handler.handle(req, ctx, rest)
    ["api", "account", "password"] ->
      case req.method {
        Post -> account.update_password(req, ctx)
        _ -> wisp.method_not_allowed([Post])
      }
    ["login"] -> pages.login_page(req, ctx)
    ["register"] -> pages.register_page(req, ctx)
    ["account"] -> pages.account_page(req, ctx)
    [] -> pages.landing_page(req, ctx)
    _ -> wisp.not_found()
  }
}

fn static_directory() -> String {
  case wisp.priv_directory("gleam_pds") {
    Ok(dir) -> dir <> "/static"
    Error(_) -> "priv/static"
  }
}

fn handle_health() -> Response {
  response.json_response(
    200,
    json.object([
      #("version", json.string("0.1.0")),
    ]),
  )
}

fn handle_xrpc(req: Request, ctx: Context, method: String) -> Response {
  case method, req.method {
    "com.atproto.server.describeServer", Get -> server.describe_server(req, ctx)
    "com.atproto.server.createAccount", Post ->
      ratelimit.guard(
        ctx,
        ratelimit.create_account_limits(),
        ratelimit.ip_key(req),
        fn() { server.create_account(req, ctx) },
      )
    "com.atproto.server.createSession", Post ->
      ratelimit.guard(
        ctx,
        ratelimit.create_session_limits(),
        ratelimit.ip_key(req),
        fn() { server.create_session(req, ctx) },
      )
    "com.atproto.server.getSession", Get -> server.get_session(req, ctx)
    "com.atproto.server.refreshSession", Post ->
      ratelimit.guard(
        ctx,
        ratelimit.refresh_limits(),
        ratelimit.credential_key(req),
        fn() { server.refresh_session(req, ctx) },
      )
    "com.atproto.server.deleteSession", Post ->
      server.delete_session(req, ctx)
    "com.atproto.server.getServiceAuth", Get ->
      server.get_service_auth(req, ctx)
    "com.atproto.identity.resolveHandle", Get ->
      identity.resolve_handle(req, ctx)
    "com.atproto.identity.resolveDid", Get -> identity.resolve_did(req, ctx)
    "com.atproto.identity.resolveIdentity", Get ->
      identity.resolve_identity(req, ctx)
    "com.atproto.identity.updateHandle", Post ->
      identity.update_handle(req, ctx)
    "com.atproto.identity.getRecommendedDidCredentials", Get ->
      identity.get_recommended_did_credentials(req, ctx)
    "com.atproto.identity.signPlcOperation", Post ->
      identity.sign_plc_operation(req, ctx)
    "com.atproto.identity.submitPlcOperation", Post ->
      identity.submit_plc_operation(req, ctx)
    "com.atproto.server.deactivateAccount", Post ->
      account.deactivate_account(req, ctx)
    "com.atproto.server.activateAccount", Post ->
      account.activate_account(req, ctx)
    "com.atproto.server.getAccountStatus", Get ->
      account.get_account_status(req, ctx)
    "com.atproto.server.checkAccountStatus", Get ->
      account.get_account_status(req, ctx)
    "com.atproto.server.deleteAccount", Post ->
      account.delete_account(req, ctx)
    "com.atproto.server.createAppPassword", Post ->
      account.create_app_password(req, ctx)
    "com.atproto.server.listAppPasswords", Get ->
      account.list_app_passwords(req, ctx)
    "com.atproto.server.revokeAppPassword", Post ->
      account.revoke_app_password(req, ctx)
    "com.atproto.repo.describeRepo", Get -> repo.describe_repo(req, ctx)
    "com.atproto.repo.getRecord", Get -> repo.get_record(req, ctx)
    "com.atproto.repo.listRecords", Get -> repo.list_records(req, ctx)
    "com.atproto.repo.createRecord", Post ->
      write_guard(req, ctx, fn() { repo.create_record(req, ctx) })
    "com.atproto.repo.putRecord", Post ->
      write_guard(req, ctx, fn() { repo.put_record(req, ctx) })
    "com.atproto.repo.deleteRecord", Post ->
      write_guard(req, ctx, fn() { repo.delete_record(req, ctx) })
    "com.atproto.repo.uploadBlob", Post ->
      write_guard(req, ctx, fn() { repo.upload_blob(req, ctx) })
    "com.atproto.repo.applyWrites", Post ->
      write_guard(req, ctx, fn() { repo.apply_writes(req, ctx) })
    "com.atproto.sync.getRepo", Get -> sync.get_repo(req, ctx)
    "com.atproto.sync.getRecord", Get -> sync.get_record(req, ctx)
    "com.atproto.sync.getBlob", Get -> sync.get_blob(req, ctx)
    "com.atproto.sync.listBlobs", Get -> sync.list_blobs(req, ctx)
    "com.atproto.sync.listRepos", Get -> sync.list_repos(req, ctx)
    "com.atproto.sync.getLatestCommit", Get -> sync.get_latest_commit(req, ctx)
    "com.atproto.sync.getRepoStatus", Get -> sync.get_repo_status(req, ctx)
    // com.atproto.space.* (permissioned-data scaffold — stubs)
    "com.atproto.space.listSpaces", Get -> space.list_spaces(req, ctx)
    "com.atproto.space.getSpace", Get -> space.get_space(req, ctx)
    "com.atproto.space.getSpaceCredential", Post ->
      space.get_space_credential(req, ctx)
    "com.atproto.space.notifySpaceDeleted", Post ->
      space.notify_space_deleted(req, ctx)
    "com.atproto.space.applyWrites", Post -> space.apply_writes(req, ctx)
    "com.atproto.space.createRecord", Post -> space.create_record(req, ctx)
    "com.atproto.space.putRecord", Post -> space.put_record(req, ctx)
    "com.atproto.space.deleteRecord", Post -> space.delete_record(req, ctx)
    "com.atproto.space.getRecord", Get -> space.get_record(req, ctx)
    "com.atproto.space.listRecords", Get -> space.list_records(req, ctx)
    "com.atproto.space.getRepo", Get -> space.get_repo(req, ctx)
    "com.atproto.space.getLatestCommit", Get ->
      space.get_latest_commit(req, ctx)
    "com.atproto.space.listRepos", Get -> space.list_repos(req, ctx)
    "com.atproto.space.listRepoOps", Get -> space.list_repo_ops(req, ctx)
    "com.atproto.space.getBlob", Get -> space.get_blob(req, ctx)
    "com.atproto.space.getDelegationToken", Get ->
      space.get_delegation_token(req, ctx)
    "com.atproto.space.notifyWrite", Post -> space.notify_write(req, ctx)
    "com.atproto.space.registerNotify", Post -> space.register_notify(req, ctx)
    // com.atproto.simplespace.* (permissioned-data scaffold — stubs)
    "com.atproto.simplespace.createSpace", Post ->
      simplespace.create_space(req, ctx)
    "com.atproto.simplespace.updateSpace", Post ->
      simplespace.update_space(req, ctx)
    "com.atproto.simplespace.deleteSpace", Post ->
      simplespace.delete_space(req, ctx)
    "com.atproto.simplespace.addMember", Post ->
      simplespace.add_member(req, ctx)
    "com.atproto.simplespace.removeMember", Post ->
      simplespace.remove_member(req, ctx)
    "com.atproto.simplespace.listMembers", Get ->
      simplespace.list_members(req, ctx)
    "com.atproto.simplespace.checkUserAccess", Get ->
      simplespace.check_user_access(req, ctx)
    // Preferences stored locally on PDS
    "app.bsky.actor.getPreferences", Get -> proxy.get_preferences(req, ctx)
    "app.bsky.actor.putPreferences", Post -> proxy.put_preferences(req, ctx)
    // Proxy app.bsky.* and chat.bsky.* to appview
    _, _ -> {
      case
        string.starts_with(method, "app.bsky.")
        || string.starts_with(method, "chat.bsky.")
      {
        True ->
          case req.method {
            Get -> proxy.proxy_get(req, ctx, method)
            Post -> proxy.proxy_post(req, ctx, method)
            _ -> wisp.method_not_allowed([Get, Post])
          }
        False ->
          response.xrpc_error(
            400,
            "MethodNotImplemented",
            "Method not found: " <> method,
          )
      }
    }
  }
}

/// Rate limit repo writes per credential (falling back to the client IP for
/// unauthenticated requests, which the handler will reject anyway).
fn write_guard(req: Request, ctx: Context, next: fn() -> Response) -> Response {
  ratelimit.guard(
    ctx,
    ratelimit.write_limits(),
    ratelimit.credential_key(req),
    next,
  )
}

/// Serve /.well-known/did.json for the server's OWN did:web identity so relays
/// can resolve the PDS. Without this, relays 404 resolving did:web:<hostname>.
fn handle_did_json(req: Request, ctx: Context) -> Response {
  case req.method {
    Get ->
      response.json_response(
        200,
        did.server_did_document(ctx.config.hostname, ctx.config.public_url),
      )
    _ -> wisp.method_not_allowed([Get])
  }
}

fn handle_atproto_did(req: Request, ctx: Context) -> Response {
  case req.method {
    Get -> {
      // Check the Host header to support wildcard handle resolution
      // e.g. brookie.booksky.app/.well-known/atproto-did -> did for brookie.booksky.app
      let host =
        list.key_find(req.headers, "host")
        |> result.unwrap(ctx.config.hostname)
        // Strip port if present
        |> string.split(":")
        |> list.first
        |> result.unwrap(ctx.config.hostname)

      case host == ctx.config.hostname {
        // Request to the PDS hostname itself — return server DID
        True -> {
          let did =
            "did:web:" <> string.replace(ctx.config.hostname, ":", "%3A")
          wisp.response(200)
          |> wisp.set_header("content-type", "text/plain")
          |> wisp.set_body(wisp.Text(did))
        }
        // Request to a handle subdomain — look up the user
        False -> {
          let result =
            sqlight.query(
              "SELECT did FROM accounts WHERE handle = ? LIMIT 1",
              ctx.db,
              [sqlight.text(host)],
              decode.at([0], decode.string),
            )
          case result {
            Ok([user_did]) ->
              wisp.response(200)
              |> wisp.set_header("content-type", "text/plain")
              |> wisp.set_body(wisp.Text(user_did))
            _ -> wisp.not_found()
          }
        }
      }
    }
    _ -> wisp.method_not_allowed([Get])
  }
}

fn cors_middleware(
  req: Request,
  next: fn() -> Response,
) -> Response {
  case req.method {
    Options -> {
      wisp.ok()
      |> wisp.set_header("access-control-allow-origin", "*")
      |> wisp.set_header(
        "access-control-allow-methods",
        "GET, POST, PUT, DELETE, OPTIONS",
      )
      |> wisp.set_header(
        "access-control-allow-headers",
        "Content-Type, Authorization, DPoP, atproto-accept-labelers, atproto-proxy, x-bsky-topics",
      )
      |> wisp.set_header("access-control-max-age", "86400")
    }
    _ -> {
      let resp = next()
      resp
      |> wisp.set_header("access-control-allow-origin", "*")
      |> wisp.set_header("access-control-expose-headers", "*")
    }
  }
}
