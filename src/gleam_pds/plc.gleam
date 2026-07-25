/// PLC Directory integration — register did:plc identities

import gleam_pds/crypto
import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/httpc
import gleam/int
import gleam/io
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}

pub type PlcResult {
  PlcResult(did: String, operation_json: String)
}

/// did:key for the server rotation key (which is configured as a raw private
/// key, so the public half is derived here).
pub fn rotation_did_key(rotation_private_key: BitArray) -> String {
  public_key_to_did_key(crypto.p256_public_from_private(rotation_private_key))
}

/// Create a PLC genesis operation, derive the DID, and register it.
/// Returns the DID string on success.
///
/// With a dedicated server rotation key, the new DID lists ONLY that key in
/// rotationKeys — the account signing key cannot rewrite the DID. Without
/// one, the account signing key doubles as the rotation key (legacy).
pub fn create_and_register(
  private_key: BitArray,
  public_key: BitArray,
  handle: String,
  pds_endpoint: String,
  rotation_key: Option(BitArray),
) -> Result(String, String) {
  // Convert public key to did:key format
  let pub_did_key = crypto_public_key_to_did_key(public_key)
  // The genesis op must be signed by one of its own rotationKeys.
  let #(signer, rotation_did_keys) = case rotation_key {
    Some(rot_priv) -> #(rot_priv, [rotation_did_key(rot_priv)])
    None -> #(private_key, [pub_did_key])
  }

  // Create the signed operation and derive DID
  let plc_result =
    create_plc_operation(
      signer,
      pub_did_key,
      handle,
      pds_endpoint,
      rotation_did_keys,
    )

  io.println("[plc] Created DID: " <> plc_result.did)
  io.println("[plc] Registering with plc.directory...")

  // POST to plc.directory
  let url = "https://plc.directory/" <> plc_result.did
  case request.to(url) {
    Error(_) -> Error("Invalid PLC directory URL")
    Ok(req) -> {
      let req =
        req
        |> request.set_method(http.Post)
        |> request.set_header("content-type", "application/json")
        |> request.set_body(plc_result.operation_json)

      case httpc.send(req) {
        Ok(resp) -> {
          io.println("[plc] Response: " <> int.to_string(resp.status))
          case resp.status {
            200 -> Ok(plc_result.did)
            204 -> Ok(plc_result.did)
            _ -> {
              io.println("[plc] Error body: " <> resp.body)
              Error("PLC registration failed: " <> resp.body)
            }
          }
        }
        Error(_) -> Error("Failed to contact PLC directory")
      }
    }
  }
}

@external(erlang, "gleam_pds_plc_ffi", "create_plc_operation")
fn create_plc_operation_ffi(
  signer_private_key: BitArray,
  pub_did_key: String,
  handle: String,
  pds_endpoint: String,
  rotation_did_keys: List(String),
) -> #(String, String)

fn create_plc_operation(
  signer_private_key: BitArray,
  pub_did_key: String,
  handle: String,
  pds_endpoint: String,
  rotation_did_keys: List(String),
) -> PlcResult {
  let #(did, op_json) =
    create_plc_operation_ffi(
      signer_private_key,
      pub_did_key,
      handle,
      pds_endpoint,
      rotation_did_keys,
    )
  PlcResult(did: did, operation_json: op_json)
}

fn crypto_public_key_to_did_key(public_key: BitArray) -> String {
  public_key_to_did_key(public_key)
}

@external(erlang, "gleam_pds_crypto_ffi", "public_key_to_did_key")
fn public_key_to_did_key(public_key: BitArray) -> String

/// Public helper: convert a raw P-256 public key to a did:key string.
pub fn did_key_for_public_key(public_key: BitArray) -> String {
  public_key_to_did_key(public_key)
}

// ---------------------------------------------------------------------------
// Non-genesis PLC operations (updateHandle, key rotation)
// ---------------------------------------------------------------------------

@external(erlang, "gleam_pds_plc_ffi", "create_plc_update_operation")
fn create_plc_update_operation_ffi(
  signer_private_key: BitArray,
  pub_did_key: String,
  handle: String,
  pds_endpoint: String,
  rotation_did_keys: List(String),
  prev: String,
) -> String

/// Build and sign a non-genesis PLC operation (with `prev` set to the previous
/// op CID) that updates alsoKnownAs to the given handle. Returns the op JSON.
/// Pass "" for `prev_cid` to produce a genesis-shaped (prev: null) op.
///
/// `current_rotation_keys` is the rotationKeys list of the DID's latest PLC
/// op (from `fetch_last_op`): the op must be signed by one of those keys.
/// When a dedicated server rotation key is configured, the emitted op always
/// lists it as the sole rotation key — a DID created before the server key
/// existed gets migrated to it by its next update, which is signed with the
/// account key (still a rotation key at that point).
pub fn create_update_operation(
  private_key: BitArray,
  public_key: BitArray,
  rotation_key: Option(BitArray),
  current_rotation_keys: List(String),
  handle: String,
  pds_endpoint: String,
  prev_cid: String,
) -> String {
  let pub_did_key = public_key_to_did_key(public_key)
  let #(signer, rotation_did_keys) = case rotation_key {
    Some(rot_priv) -> {
      let rot_did = rotation_did_key(rot_priv)
      case list.contains(current_rotation_keys, rot_did) {
        True -> #(rot_priv, [rot_did])
        False -> #(private_key, [rot_did])
      }
    }
    None -> #(private_key, [pub_did_key])
  }
  create_plc_update_operation_ffi(
    signer,
    pub_did_key,
    handle,
    pds_endpoint,
    rotation_did_keys,
    prev_cid,
  )
}

/// Fetch the most recent operation in the DID's PLC audit log: its CID
/// (needed as `prev` in an update) and its rotationKeys (which decide what
/// key must sign that update).
pub fn fetch_last_op(did: String) -> Result(#(String, List(String)), String) {
  let url = "https://plc.directory/" <> did <> "/log/audit"
  case request.to(url) {
    Error(_) -> Error("Invalid PLC directory URL")
    Ok(req0) -> {
      let req = request.set_method(req0, http.Get)
      case httpc.send(req) {
        Ok(resp) ->
          case resp.status {
            200 -> parse_last_op(resp.body)
            _ -> Error("PLC audit fetch failed: " <> int.to_string(resp.status))
          }
        Error(_) -> Error("Failed to contact PLC directory")
      }
    }
  }
}

fn parse_last_op(body: String) -> Result(#(String, List(String)), String) {
  // Tombstone ops carry no rotationKeys, hence the [] default.
  let entry_decoder = {
    use cid <- decode.field("cid", decode.string)
    use rotation_keys <- decode.field("operation", {
      use keys <- decode.optional_field(
        "rotationKeys",
        [],
        decode.list(decode.string),
      )
      decode.success(keys)
    })
    decode.success(#(cid, rotation_keys))
  }
  case json.parse(from: body, using: decode.list(entry_decoder)) {
    Ok(entries) ->
      case list.last(entries) {
        Ok(last) -> Ok(last)
        Error(_) -> Error("No PLC operations found for DID")
      }
    Error(_) -> Error("Failed to parse PLC audit log")
  }
}

/// Submit an already-signed PLC operation JSON to the PLC directory.
pub fn submit_operation(did: String, op_json: String) -> Result(Nil, String) {
  let url = "https://plc.directory/" <> did
  case request.to(url) {
    Error(_) -> Error("Invalid PLC directory URL")
    Ok(req0) -> {
      let req =
        req0
        |> request.set_method(http.Post)
        |> request.set_header("content-type", "application/json")
        |> request.set_body(op_json)
      case httpc.send(req) {
        Ok(resp) ->
          case resp.status {
            200 -> Ok(Nil)
            204 -> Ok(Nil)
            _ -> Error("PLC submit failed: " <> resp.body)
          }
        Error(_) -> Error("Failed to contact PLC directory")
      }
    }
  }
}
