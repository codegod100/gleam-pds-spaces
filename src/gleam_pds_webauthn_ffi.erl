-module(gleam_pds_webauthn_ffi).
-export([
    parse_attestation_object/1,
    parse_authenticator_data/1,
    verify_assertion/4
]).

%% Parse a CBOR-encoded attestation object.
%% Returns {ok, #{auth_data, public_key_bytes, credential_id}} or {error, Reason}.
parse_attestation_object(B64AttObj) ->
    try
        Bin = base64url_decode_bin(B64AttObj),
        %% Minimal CBOR map parsing for attestation object
        %% The attestation object is a CBOR map with keys:
        %%   "fmt" -> string, "attStmt" -> map, "authData" -> bytes
        AuthData = extract_cbor_authdata(Bin),
        parse_auth_data_result(AuthData)
    catch
        _:Reason ->
            {error, list_to_binary(io_lib:format("~p", [Reason]))}
    end.

%% Parse raw authenticator data (from assertion response)
parse_authenticator_data(B64AuthData) ->
    try
        Bin = base64url_decode_bin(B64AuthData),
        parse_auth_data_result(Bin)
    catch
        _:Reason ->
            {error, list_to_binary(io_lib:format("~p", [Reason]))}
    end.

parse_auth_data_result(AuthData) when byte_size(AuthData) >= 37 ->
    <<RpIdHash:32/binary, Flags:1/binary, SignCount:32/big, Rest/binary>> = AuthData,
    <<FlagByte>> = Flags,
    HasAttestedCred = (FlagByte band 16#40) =/= 0,
    UserPresent = (FlagByte band 16#01) =/= 0,
    UserVerified = (FlagByte band 16#04) =/= 0,
    case HasAttestedCred andalso byte_size(Rest) > 18 of
        true ->
            %% Parse attested credential data
            <<_AAGUID:16/binary, CredIdLen:16/big, CredId:CredIdLen/binary, PubKeyRest/binary>> = Rest,
            %% PubKeyRest starts with a CBOR-encoded public key (COSE_Key)
            %% For ES256 (alg -7), it's a CBOR map with keys:
            %%   1 (kty) -> 2 (EC2), 3 (alg) -> -7, -1 (crv) -> 1 (P-256)
            %%   -2 (x) -> 32 bytes, -3 (y) -> 32 bytes
            PubKey = extract_cose_pubkey(PubKeyRest),
            {ok, #{
                <<"rp_id_hash">> => RpIdHash,
                <<"flags">> => FlagByte,
                <<"sign_count">> => SignCount,
                <<"credential_id">> => base64url_encode_bin(CredId),
                <<"public_key">> => PubKey,
                <<"user_present">> => bool_to_int(UserPresent),
                <<"user_verified">> => bool_to_int(UserVerified)
            }};
        false ->
            %% No attested credential (assertion response)
            {ok, #{
                <<"rp_id_hash">> => RpIdHash,
                <<"flags">> => FlagByte,
                <<"sign_count">> => SignCount,
                <<"credential_id">> => <<>>,
                <<"public_key">> => <<>>,
                <<"user_present">> => bool_to_int(UserPresent),
                <<"user_verified">> => bool_to_int(UserVerified)
            }}
    end;
parse_auth_data_result(_) ->
    {error, <<"authenticator data too short">>}.

%% Extract authData from CBOR attestation object
%% This is a simplified CBOR parser that looks for the authData field
extract_cbor_authdata(Bin) ->
    %% The attestation object is a CBOR map (major type 5)
    %% We need to find the "authData" key and extract its byte string value
    %% Simple approach: scan for the "authData" string and grab the next byte string
    case binary:match(Bin, <<"authData">>) of
        {Pos, Len} ->
            AfterKey = Pos + Len,
            %% The value after the key should be a CBOR byte string
            extract_cbor_bytestring(Bin, AfterKey);
        nomatch ->
            error(no_authdata_field)
    end.

extract_cbor_bytestring(Bin, Offset) ->
    <<_:Offset/binary, Rest/binary>> = Bin,
    scan_for_bytestring(Rest).

scan_for_bytestring(<<2#010:3, Len:5, Data:Len/binary, _/binary>>) when Len < 24 -> Data;
scan_for_bytestring(<<16#58, Len:8, Data:Len/binary, _/binary>>) -> Data;
scan_for_bytestring(<<16#59, Len:16/big, Data:Len/binary, _/binary>>) -> Data;
scan_for_bytestring(<<_, Rest/binary>>) -> scan_for_bytestring(Rest);
scan_for_bytestring(<<>>) -> error(no_bytestring_found).

%% Extract X,Y coordinates from a COSE_Key CBOR structure.
%% Returns a 65-byte uncompressed EC point (04 || X || Y).
%%
%% COSE_Key for ES256 is a CBOR map where:
%%   key  1 (kty) -> 2 (EC2)
%%   key  3 (alg) -> -7
%%   key -1 (crv) -> 1 (P-256)
%%   key -2 (x)   -> 32-byte byte string (CBOR `0x58 0x20 <32 bytes>`)
%%   key -3 (y)   -> 32-byte byte string
%%
%% In CBOR, the negative integer key -2 encodes as `0x21` and -3 as `0x22`.
extract_cose_pubkey(CborData) ->
    X = find_cose_coord(CborData, <<16#21, 16#58, 16#20>>),
    Y = find_cose_coord(CborData, <<16#22, 16#58, 16#20>>),
    case {X, Y} of
        {<<XB:32/binary>>, <<YB:32/binary>>} ->
            <<4, XB/binary, YB/binary>>;
        _ ->
            <<>>
    end.

find_cose_coord(Bin, Marker) ->
    case binary:match(Bin, Marker) of
        nomatch -> <<>>;
        {Pos, Len} ->
            Start = Pos + Len,
            case Bin of
                <<_:Start/binary, Coord:32/binary, _/binary>> -> Coord;
                _ -> <<>>
            end
    end.

%% Verify a WebAuthn assertion signature
%% authenticator_data and client_data_json are base64url-encoded
%% signature is base64url-encoded DER signature
%% public_key is 65-byte uncompressed EC point
verify_assertion(B64AuthData, B64ClientDataJSON, B64Signature, PublicKey) ->
    try
        AuthData = base64url_decode_bin(B64AuthData),
        ClientDataJSON = base64url_decode_bin(B64ClientDataJSON),
        Signature = base64url_decode_bin(B64Signature),
        
        %% The signed data is: authenticatorData || SHA-256(clientDataJSON)
        ClientDataHash = crypto:hash(sha256, ClientDataJSON),
        SignedData = <<AuthData/binary, ClientDataHash/binary>>,
        
        %% Verify ECDSA signature
        case PublicKey of
            <<4, _:64/binary>> ->
                %% Uncompressed point
                crypto:verify(ecdsa, sha256, SignedData, Signature, [PublicKey, secp256r1]);
            _ ->
                false
        end
    catch
        _:_ -> false
    end.

%% Helpers
bool_to_int(true) -> 1;
bool_to_int(false) -> 0.

base64url_decode_bin(B64) when is_binary(B64) ->
    B = binary:replace(
        binary:replace(B64, <<"-">>, <<"+">>, [global]),
        <<"_">>, <<"/">>, [global]),
    Padded = case byte_size(B) rem 4 of
        0 -> B;
        2 -> <<B/binary, "==">>;
        3 -> <<B/binary, "=">>;
        _ -> B
    end,
    base64:decode(Padded).

base64url_encode_bin(Bin) ->
    B64 = base64:encode(Bin),
    binary:replace(
        binary:replace(
            binary:replace(B64, <<"+">>, <<"-">>, [global]),
            <<"/">>, <<"_">>, [global]),
        <<"=">>, <<>>, [global]).
