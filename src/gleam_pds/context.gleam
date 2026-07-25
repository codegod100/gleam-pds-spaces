import gleam_pds/config.{type Config}
import gleam_pds/firehose
import gleam/erlang/process
import sqlight

pub type Context {
  Context(
    db: sqlight.Connection,
    config: Config,
    firehose: process.Subject(firehose.Message),
  )
}
