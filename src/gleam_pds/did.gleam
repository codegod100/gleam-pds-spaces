/// DID (Decentralized Identifier) handling for AT Protocol
/// Supports did:web and did:plc

import gleam/json
import gleam/string

pub type Did {
  Did(value: String)
}

/// Generate a did:plc identifier from random bytes
@external(erlang, "gleam_pds_crypto_ffi", "generate_random_did")
pub fn generate_plc() -> String

/// Create a did:web identifier from a hostname
pub fn web(hostname: String) -> String {
  "did:web:" <> string.replace(hostname, ":", "%3A")
}

/// Get the DID document for a did:web
pub fn web_did_document(
  did: String,
  public_key_jwk: json.Json,
  service_endpoint: String,
) -> json.Json {
  json.object([
    #("@context", json.array(
      ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1", "https://w3id.org/security/suites/jws-2020/v1"],
      json.string,
    )),
    #("id", json.string(did)),
    #("verificationMethod", json.preprocessed_array([
      json.object([
        #("id", json.string(did <> "#atproto")),
        #("type", json.string("EcdsaSecp256r1VerificationKey2019")),
        #("controller", json.string(did)),
        #("publicKeyJwk", public_key_jwk),
      ]),
    ])),
    #("service", json.preprocessed_array([
      json.object([
        #("id", json.string("#atproto_pds")),
        #("type", json.string("AtprotoPersonalDataServer")),
        #("serviceEndpoint", json.string(service_endpoint)),
      ]),
    ])),
  ])
}

/// Create a DID for a user (using did:plc for now)
pub fn create_for_user() -> String {
  generate_plc()
}

/// Build the DID document served at /.well-known/did.json for the server's OWN
/// did:web identity. Relays resolve this to find the PDS service endpoint; if it
/// 404s, relays cannot resolve the PDS. A verificationMethod is intentionally
/// omitted because this PDS does not currently hold a dedicated server signing
/// key (see did:web note in the guide, section 6.2) — the service entry is what
/// federation actually requires.
pub fn server_did_document(hostname: String, service_endpoint: String) -> json.Json {
  let did = web(hostname)
  json.object([
    #(
      "@context",
      json.array(["https://www.w3.org/ns/did/v1"], json.string),
    ),
    #("id", json.string(did)),
    #(
      "service",
      json.preprocessed_array([
        json.object([
          #("id", json.string("#atproto_pds")),
          #("type", json.string("AtprotoPersonalDataServer")),
          #("serviceEndpoint", json.string(service_endpoint)),
        ]),
      ]),
    ),
  ])
}
