import gleam_pds/config
import gleam_pds/context.{Context}
import gleam_pds/db
import gleam_pds/firehose
import gleam_pds/ratelimit
import gleam_pds/router
import gleam/erlang/process
import gleam/http/request
import gleam/int
import gleam/io
import mist
import wisp
import wisp/wisp_mist

pub fn main() {
  wisp.configure_logger()
  let cfg = config.load()

  io.println("")
  io.println("\u{2728} Gleam PDS - AT Protocol Personal Data Server")
  io.println("")
  io.println("  Hostname:  " <> cfg.hostname)
  io.println("  Port:      " <> int.to_string(cfg.port))
  io.println("  Public:    " <> cfg.public_url)
  io.println("  Database:  " <> cfg.db_path)
  io.println("  DID:       did:web:" <> cfg.hostname)
  io.println("")

  // Open database and run migrations
  let assert Ok(conn) = db.connect(cfg.db_path)
  let assert Ok(Nil) = db.migrate(conn)
  io.println("Database initialized")

  // Start the firehose actor
  let assert Ok(firehose_subject) = firehose.start(conn)
  io.println("Firehose actor started")

  // Create the rate-limit ETS table up front, owned by this (never-exiting)
  // process so it outlives individual request handlers.
  ratelimit.init()
  case cfg.ratelimit_disabled {
    True -> io.println("Rate limiting DISABLED (GLEAM_PDS_RATELIMIT_DISABLED)")
    False -> io.println("Rate limiting enabled")
  }

  let ctx = Context(db: conn, config: cfg, firehose: firehose_subject)

  // Set up the wisp handler for normal HTTP requests
  let wisp_handler =
    wisp_mist.handler(
      fn(req) { router.handle_request(req, ctx) },
      cfg.secret_key,
    )

  // Custom mist handler that intercepts WebSocket requests for subscribeRepos
  let mist_handler = fn(req: request.Request(mist.Connection)) {
    case request.path_segments(req) {
      ["xrpc", "com.atproto.sync.subscribeRepos"] ->
        firehose.handle_websocket(req, firehose_subject, conn)
      _ -> wisp_handler(req)
    }
  }

  let assert Ok(_) =
    mist_handler
    |> mist.new
    |> mist.port(cfg.port)
    |> mist.bind("0.0.0.0")
    |> mist.start

  io.println("Server listening on port " <> int.to_string(cfg.port))
  io.println("Firehose available at ws://" <> cfg.hostname <> ":" <> int.to_string(cfg.port) <> "/xrpc/com.atproto.sync.subscribeRepos")
  io.println("")

  process.sleep_forever()
}
