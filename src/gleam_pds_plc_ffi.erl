-module(gleam_pds_plc_ffi).
-export([
    create_plc_operation/5,
    create_plc_update_operation/6,
    encode_dag_cbor/1,
    derive_did_plc/1,
    der_to_raw_es256/1
]).

%% Create a signed PLC genesis operation and derive the DID.
%% Returns {did, signed_operation_json}
create_plc_operation(SignerPrivKey, PubKeyDidKey, Handle, PdsEndpoint, RotationDidKeys) ->
    %% Build unsigned operation (without sig field)
    UnsignedOp = {map, [
        {<<"type">>, <<"plc_operation">>},
        {<<"verificationMethods">>, [{<<"atproto">>, PubKeyDidKey}]},
        {<<"rotationKeys">>, RotationDidKeys},
        {<<"alsoKnownAs">>, [<<"at://", Handle/binary>>]},
        {<<"services">>, [{<<"atproto_pds">>, [
            {<<"type">>, <<"AtprotoPersonalDataServer">>},
            {<<"endpoint">>, PdsEndpoint}
        ]}]},
        {<<"prev">>, null}
    ]},
    %% DAG-CBOR encode the unsigned op for signing
    UnsignedCbor = encode_dag_cbor(UnsignedOp),
    %% Sign with ES256 (low-S normalized)
    DerSig = crypto:sign(ecdsa, sha256, UnsignedCbor, [SignerPrivKey, secp256r1]),
    %% Convert DER signature to raw r||s (64 bytes) with low-S
    RawSig = der_to_raw_es256(DerSig),
    %% base64url encode signature
    SigB64 = base64url_encode(RawSig),
    %% Build signed operation: sig is a STRING (base64url) in CBOR, not bytes!
    SignedOp = {map, [
        {<<"sig">>, SigB64},
        {<<"prev">>, null},
        {<<"type">>, <<"plc_operation">>},
        {<<"services">>, [{<<"atproto_pds">>, [
            {<<"type">>, <<"AtprotoPersonalDataServer">>},
            {<<"endpoint">>, PdsEndpoint}
        ]}]},
        {<<"alsoKnownAs">>, [<<"at://", Handle/binary>>]},
        {<<"rotationKeys">>, RotationDidKeys},
        {<<"verificationMethods">>, [{<<"atproto">>, PubKeyDidKey}]}
    ]},
    %% Derive DID: CBOR-encode the signed op (sig as string), SHA-256, base32 first 24 chars
    SignedCbor = encode_dag_cbor(SignedOp),
    Did = derive_did_plc(SignedCbor),
    %% Build JSON for HTTP POST
    OpJsonPairs = [
        {<<"sig">>, SigB64},
        {<<"prev">>, null},
        {<<"type">>, <<"plc_operation">>},
        {<<"services">>, [{<<"atproto_pds">>, [
            {<<"type">>, <<"AtprotoPersonalDataServer">>},
            {<<"endpoint">>, PdsEndpoint}
        ]}]},
        {<<"alsoKnownAs">>, [<<"at://", Handle/binary>>]},
        {<<"rotationKeys">>, RotationDidKeys},
        {<<"verificationMethods">>, [{<<"atproto">>, PubKeyDidKey}]}
    ],
    OpJson = encode_op_json(OpJsonPairs),
    {Did, OpJson}.

%% Create a signed NON-genesis PLC operation (prev != null).
%% Used for updateHandle (change alsoKnownAs) and key rotation.
%% Prev is the base32 CID string of the previous operation; pass <<>> for genesis.
%% Returns the signed operation JSON (the DID does not change on an update).
create_plc_update_operation(SignerPrivKey, PubKeyDidKey, Handle, PdsEndpoint, RotationDidKeys, Prev) ->
    PrevVal = case Prev of
        <<>> -> null;
        _ -> Prev
    end,
    %% Build unsigned operation (without sig field)
    UnsignedOp = {map, [
        {<<"type">>, <<"plc_operation">>},
        {<<"verificationMethods">>, [{<<"atproto">>, PubKeyDidKey}]},
        {<<"rotationKeys">>, RotationDidKeys},
        {<<"alsoKnownAs">>, [<<"at://", Handle/binary>>]},
        {<<"services">>, [{<<"atproto_pds">>, [
            {<<"type">>, <<"AtprotoPersonalDataServer">>},
            {<<"endpoint">>, PdsEndpoint}
        ]}]},
        {<<"prev">>, PrevVal}
    ]},
    UnsignedCbor = encode_dag_cbor(UnsignedOp),
    DerSig = crypto:sign(ecdsa, sha256, UnsignedCbor, [SignerPrivKey, secp256r1]),
    RawSig = der_to_raw_es256(DerSig),
    SigB64 = base64url_encode(RawSig),
    %% Build JSON for HTTP POST to plc.directory
    OpJsonPairs = [
        {<<"sig">>, SigB64},
        {<<"prev">>, PrevVal},
        {<<"type">>, <<"plc_operation">>},
        {<<"services">>, [{<<"atproto_pds">>, [
            {<<"type">>, <<"AtprotoPersonalDataServer">>},
            {<<"endpoint">>, PdsEndpoint}
        ]}]},
        {<<"alsoKnownAs">>, [<<"at://", Handle/binary>>]},
        {<<"rotationKeys">>, RotationDidKeys},
        {<<"verificationMethods">>, [{<<"atproto">>, PubKeyDidKey}]}
    ],
    encode_op_json(OpJsonPairs).

%% Derive did:plc from CBOR-encoded genesis operation
%% SHA-256 hash, base32-encode, take first 24 characters
derive_did_plc(CborBytes) ->
    Hash = crypto:hash(sha256, CborBytes),
    Encoded = base32_lower_encode(Hash),
    Truncated = binary:part(Encoded, 0, 24),
    <<"did:plc:", Truncated/binary>>.

%% DAG-CBOR encoding
%% Maps must have keys sorted by byte length then lexicographically
encode_dag_cbor(null) ->
    <<16#F6>>;  %% CBOR null
encode_dag_cbor(true) ->
    <<16#F5>>;  %% CBOR true
encode_dag_cbor(false) ->
    <<16#F4>>;  %% CBOR false
encode_dag_cbor({bytes, Bin}) when is_binary(Bin) ->
    %% CBOR byte string (major type 2)
    cbor_encode_length(2, byte_size(Bin), Bin);
encode_dag_cbor(Bin) when is_binary(Bin) ->
    %% CBOR text string (major type 3)
    cbor_encode_length(3, byte_size(Bin), Bin);
encode_dag_cbor(N) when is_integer(N), N >= 0 ->
    %% CBOR unsigned integer (major type 0)
    encode_cbor_uint(0, N);
encode_dag_cbor(N) when is_integer(N), N < 0 ->
    %% CBOR negative integer (major type 1)
    encode_cbor_uint(1, -1 - N);
encode_dag_cbor(List) when is_list(List) ->
    %% Check if it's a proplist (map) or array
    case List of
        [{K, _V} | _] when is_binary(K) ->
            encode_dag_cbor({map, List});
        _ ->
            %% CBOR array (major type 4)
            Encoded = [encode_dag_cbor(Item) || Item <- List],
            iolist_to_binary([encode_cbor_uint(4, length(List)) | Encoded])
    end;
encode_dag_cbor({map, Pairs}) ->
    %% DAG-CBOR: sort map keys by byte length first, then lexicographically
    Sorted = lists:sort(fun({K1, _}, {K2, _}) ->
        L1 = byte_size(K1),
        L2 = byte_size(K2),
        if L1 < L2 -> true;
           L1 > L2 -> false;
           true -> K1 =< K2
        end
    end, Pairs),
    Encoded = lists:map(fun({K, V}) ->
        [encode_dag_cbor(K), encode_dag_cbor(V)]
    end, Sorted),
    iolist_to_binary([encode_cbor_uint(5, length(Pairs)) | Encoded]).

encode_cbor_uint(Major, N) when N < 24 ->
    <<(Major bsl 5 bor N)>>;
encode_cbor_uint(Major, N) when N < 256 ->
    <<(Major bsl 5 bor 24), N:8>>;
encode_cbor_uint(Major, N) when N < 65536 ->
    <<(Major bsl 5 bor 25), N:16>>;
encode_cbor_uint(Major, N) when N < 4294967296 ->
    <<(Major bsl 5 bor 26), N:32>>;
encode_cbor_uint(Major, N) ->
    <<(Major bsl 5 bor 27), N:64>>.

cbor_encode_length(Major, Len, Data) ->
    <<(encode_cbor_uint(Major, Len))/binary, Data/binary>>.

%% Convert DER-encoded ECDSA signature to raw 64-byte r||s with low-S normalization
der_to_raw_es256(DerSig) ->
    %% Parse DER: 30 <len> 02 <rlen> <r> 02 <slen> <s>
    <<16#30, _TotalLen, 16#02, RLen, R:RLen/binary, 16#02, SLen, S:SLen/binary>> = DerSig,
    %% Pad/trim R and S to 32 bytes
    R32 = pad_or_trim(R, 32),
    S32 = pad_or_trim(S, 32),
    %% Low-S normalization for secp256r1
    N = 16#FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    SInt = binary:decode_unsigned(S32, big),
    HalfN = N div 2,
    NormS = case SInt > HalfN of
        true -> N - SInt;
        false -> SInt
    end,
    NS32 = <<NormS:256>>,
    <<R32/binary, NS32/binary>>.

pad_or_trim(Bin, Size) when byte_size(Bin) =:= Size -> Bin;
pad_or_trim(Bin, Size) when byte_size(Bin) > Size ->
    %% Trim leading zeros
    binary:part(Bin, byte_size(Bin) - Size, Size);
pad_or_trim(Bin, Size) when byte_size(Bin) < Size ->
    %% Pad with leading zeros
    Pad = Size - byte_size(Bin),
    <<0:(Pad*8), Bin/binary>>.

%% base32 lower-case encoding (RFC 4648, no padding)
base32_lower_encode(Bin) ->
    base32_lower_encode(Bin, <<>>).

base32_lower_encode(<<>>, Acc) -> Acc;
base32_lower_encode(<<A:5, Rest/bitstring>>, Acc) ->
    C = b32char(A),
    base32_lower_encode(Rest, <<Acc/binary, C>>);
base32_lower_encode(<<A:4>>, Acc) -> <<Acc/binary, (b32char(A bsl 1))>>;
base32_lower_encode(<<A:3>>, Acc) -> <<Acc/binary, (b32char(A bsl 2))>>;
base32_lower_encode(<<A:2>>, Acc) -> <<Acc/binary, (b32char(A bsl 3))>>;
base32_lower_encode(<<A:1>>, Acc) -> <<Acc/binary, (b32char(A bsl 4))>>.

b32char(N) when N >= 0, N =< 25 -> N + $a;
b32char(N) when N >= 26, N =< 31 -> N - 26 + $2.

%% base64url encode (no padding)
base64url_encode(Data) ->
    B64 = base64:encode(Data),
    binary:replace(
        binary:replace(
            binary:replace(B64, <<"+">>, <<"-">>, [global]),
            <<"/">>, <<"_">>, [global]),
        <<"=">>, <<>>, [global]).

%% Encode signed op as JSON for HTTP POST
encode_op_json(Pairs) ->
    Fields = lists:map(fun({K, V}) ->
        <<"\"", K/binary, "\":", (json_value(V))/binary>>
    end, Pairs),
    iolist_to_binary([<<"{">>, lists:join(<<",">>, Fields), <<"}">>]).

json_value(null) -> <<"null">>;
json_value(true) -> <<"true">>;
json_value(false) -> <<"false">>;
json_value(Bin) when is_binary(Bin) ->
    <<"\"", Bin/binary, "\"">>;
json_value(N) when is_integer(N) ->
    integer_to_binary(N);
json_value(List) when is_list(List) ->
    case List of
        [{K, _} | _] when is_binary(K) ->
            %% It's a map/object
            Fields = lists:map(fun({Ki, Vi}) ->
                <<"\"", Ki/binary, "\":", (json_value(Vi))/binary>>
            end, List),
            iolist_to_binary([<<"{">>, lists:join(<<",">>, Fields), <<"}">>]);
        _ ->
            %% Array
            Elems = lists:map(fun json_value/1, List),
            iolist_to_binary([<<"[">>, lists:join(<<",">>, Elems), <<"]">>])
    end.
