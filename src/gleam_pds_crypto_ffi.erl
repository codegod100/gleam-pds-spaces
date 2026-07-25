-module(gleam_pds_crypto_ffi).
-export([
    base64url_encode/1,
    base64url_decode/1,
    generate_p256_keypair/0,
    p256_public_from_private/1,
    sign_es256/2,
    verify_es256/3,
    base32_encode/1,
    base32_decode/1,
    timestamp_microseconds/0,
    first_byte/1,
    pbkdf2/3,
    generate_random_did/0,
    public_key_to_jwk/1,
    public_key_to_did_key/1,
    generate_tid/0,
    verify_dpop_es256/4,
    jwk_thumbprint/2,
    dpop_jti_seen/2
]).

base64url_encode(Data) when is_binary(Data) ->
    B64 = base64:encode(Data),
    %% Convert to URL-safe and strip padding
    binary:replace(
        binary:replace(
            binary:replace(B64, <<"+">>, <<"-">>, [global]),
            <<"/">>, <<"_">>, [global]),
        <<"=">>, <<>>, [global]).

base64url_decode(Str) when is_list(Str) ->
    base64url_decode(list_to_binary(Str));
base64url_decode(Str) when is_binary(Str) ->
    %% Convert from URL-safe
    B64 = binary:replace(
        binary:replace(Str, <<"-">>, <<"+">>, [global]),
        <<"_">>, <<"/">>, [global]),
    %% Add padding
    Padded = case byte_size(B64) rem 4 of
        0 -> B64;
        2 -> <<B64/binary, "==">>;
        3 -> <<B64/binary, "=">>;
        _ -> B64
    end,
    try
        {ok, base64:decode(Padded)}
    catch
        _:_ -> {error, nil}
    end.

generate_p256_keypair() ->
    {PubKey, PrivKey} = crypto:generate_key(ecdh, secp256r1),
    {key_pair, PrivKey, PubKey}.

%% Derive the uncompressed public point for a raw 32-byte P-256 private key.
%% Same representation as the PubKey returned by generate_p256_keypair/0.
p256_public_from_private(PrivKey) ->
    {PubKey, _} = crypto:generate_key(ecdh, secp256r1, PrivKey),
    PubKey.

sign_es256(Data, PrivKey) ->
    %% PrivKey is raw 32-byte private key, PubKey can be derived
    %% For ECDSA signing with secp256r1
    Sig = crypto:sign(ecdsa, sha256, Data, [PrivKey, secp256r1]),
    Sig.

verify_es256(Data, Signature, PubKey) ->
    try
        crypto:verify(ecdsa, sha256, Data, Signature, [PubKey, secp256r1])
    catch
        _:_ -> false
    end.

base32_encode(Data) ->
    base32_encode(Data, <<>>).

base32_encode(<<>>, Acc) ->
    Acc;
base32_encode(Data, Acc) ->
    case Data of
        <<A:5, Rest/bitstring>> ->
            Char = base32_char(A),
            base32_encode(Rest, <<Acc/binary, Char>>);
        <<A:4>> ->
            Char = base32_char(A bsl 1),
            <<Acc/binary, Char>>;
        <<A:3>> ->
            Char = base32_char(A bsl 2),
            <<Acc/binary, Char>>;
        <<A:2>> ->
            Char = base32_char(A bsl 3),
            <<Acc/binary, Char>>;
        <<A:1>> ->
            Char = base32_char(A bsl 4),
            <<Acc/binary, Char>>;
        <<>> ->
            Acc
    end.

base32_char(N) when N >= 0, N =< 25 -> N + $a;
base32_char(N) when N >= 26, N =< 31 -> N - 26 + $2.

base32_decode(Str) when is_list(Str) ->
    base32_decode(list_to_binary(Str));
base32_decode(Str) when is_binary(Str) ->
    try
        Chars = binary_to_list(Str),
        Bits = lists:foldl(fun(Char, Acc) ->
            Val = base32_unchar(Char),
            <<Acc/bitstring, Val:5>>
        end, <<>>, Chars),
        %% Trim to byte boundary
        ByteLen = bit_size(Bits) div 8,
        <<Bytes:ByteLen/binary, _/bitstring>> = Bits,
        {ok, Bytes}
    catch
        _:_ -> {error, nil}
    end.

base32_unchar(C) when C >= $a, C =< $z -> C - $a;
base32_unchar(C) when C >= $A, C =< $Z -> C - $A;
base32_unchar(C) when C >= $2, C =< $7 -> C - $2 + 26.

timestamp_microseconds() ->
    {Mega, Sec, Micro} = os:timestamp(),
    (Mega * 1000000 + Sec) * 1000000 + Micro.

generate_tid() ->
    Timestamp = timestamp_microseconds(),
    <<ClockId:16>> = crypto:strong_rand_bytes(2),
    ClockId10 = ClockId rem 1024,
    TidInt = Timestamp * 1024 + ClockId10,
    tid_to_string(TidInt, 13, <<>>).

tid_to_string(_TidInt, 0, Acc) -> Acc;
tid_to_string(TidInt, Remaining, Acc) ->
    Chars = <<"2345678abcdefghijklmnopqrstuvwxyz">>,
    Idx = TidInt rem 32,
    Char = binary:part(Chars, Idx, 1),
    tid_to_string(TidInt div 32, Remaining - 1, <<Char/binary, Acc/binary>>).

first_byte(<<B:8, _/binary>>) -> B;
first_byte(<<>>) -> 0.

pbkdf2(Password, Salt, Iterations) when is_list(Password) ->
    pbkdf2(list_to_binary(Password), Salt, Iterations);
pbkdf2(Password, Salt, Iterations) ->
    %% Use crypto:pbkdf2_hmac if available (OTP 24+), otherwise manual
    crypto:pbkdf2_hmac(sha256, Password, Salt, Iterations, 32).

generate_random_did() ->
    Rand = crypto:strong_rand_bytes(16),
    Hex = string:lowercase(binary_to_list(binary:encode_hex(Rand))),
    list_to_binary("did:plc:" ++ Hex).

public_key_to_jwk(PubKey) ->
    %% PubKey is uncompressed EC point: 04 || X (32 bytes) || Y (32 bytes)
    case PubKey of
        <<4, X:32/binary, Y:32/binary>> ->
            XB64 = list_to_binary(base64url_encode(X)),
            YB64 = list_to_binary(base64url_encode(Y)),
            #{<<"kty">> => <<"EC">>,
              <<"crv">> => <<"P-256">>,
              <<"x">> => XB64,
              <<"y">> => YB64};
        _ ->
            {error, invalid_public_key}
    end.

public_key_to_did_key(PubKey) ->
    %% Compressed public key for did:key
    Compressed = compress_p256(PubKey),
    %% multicodec prefix for P-256 is 0x1200
    MulticodecKey = <<16#80, 16#24, Compressed/binary>>,
    %% base58btc encode with 'z' prefix
    Encoded = base58_encode(MulticodecKey),
    list_to_binary("did:key:z" ++ Encoded).

compress_p256(<<4, X:32/binary, Y:32/binary>>) ->
    <<YLast>> = binary:part(Y, 31, 1),
    Prefix = case YLast rem 2 of
        0 -> 2;
        1 -> 3
    end,
    <<Prefix, X/binary>>;
compress_p256(Key) -> Key.

base58_encode(Bin) ->
    Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
    Int = binary:decode_unsigned(Bin, big),
    Encoded = base58_encode_int(Int, Alphabet, []),
    %% Add leading '1's for leading zero bytes
    LeadingZeros = count_leading_zeros(Bin, 0),
    list_to_binary(lists:duplicate(LeadingZeros, $1) ++ Encoded).

base58_encode_int(0, _Alphabet, Acc) -> Acc;
base58_encode_int(Int, Alphabet, Acc) ->
    Rem = Int rem 58,
    Char = lists:nth(Rem + 1, Alphabet),
    base58_encode_int(Int div 58, Alphabet, [Char | Acc]).

count_leading_zeros(<<0, Rest/binary>>, N) -> count_leading_zeros(Rest, N + 1);
count_leading_zeros(_, N) -> N.

%% ---- DPoP support ----

to_bin(B) when is_binary(B) -> B;
to_bin(L) when is_list(L) -> list_to_binary(L).

b64url_decode(B64) ->
    B = binary:replace(
        binary:replace(to_bin(B64), <<"-">>, <<"+">>, [global]),
        <<"_">>, <<"/">>, [global]),
    Padded = case byte_size(B) rem 4 of
        0 -> B;
        2 -> <<B/binary, "==">>;
        3 -> <<B/binary, "=">>;
        _ -> B
    end,
    base64:decode(Padded).

%% Verify an ES256 (P-256/SHA-256) JWS signature over SigningInput using the
%% JWK coordinates X and Y (base64url-encoded 32-byte values). RawSig is the
%% raw 64-byte R||S JWS signature.
verify_dpop_es256(SigningInput, RawSig, XB64, YB64) ->
    try
        X = b64url_decode(XB64),
        Y = b64url_decode(YB64),
        Sig = to_bin(RawSig),
        case {byte_size(X), byte_size(Y), byte_size(Sig)} of
            {32, 32, 64} ->
                Point = <<4, X/binary, Y/binary>>,
                Der = raw_to_der(Sig),
                crypto:verify(ecdsa, sha256, to_bin(SigningInput), Der,
                              [Point, secp256r1]);
            _ ->
                false
        end
    catch
        _:_ -> false
    end.

raw_to_der(<<R:32/binary, S:32/binary>>) ->
    RB = der_int(R),
    SB = der_int(S),
    Body = <<RB/binary, SB/binary>>,
    <<16#30, (byte_size(Body)):8, Body/binary>>.

der_int(Bin) ->
    Trimmed = trim_leading_zeros(Bin),
    Norm = case Trimmed of
        <<>> -> <<0>>;
        <<H, _/binary>> when H >= 16#80 -> <<0, Trimmed/binary>>;
        _ -> Trimmed
    end,
    <<16#02, (byte_size(Norm)):8, Norm/binary>>.

trim_leading_zeros(<<0, Rest/binary>>) when byte_size(Rest) > 0 ->
    trim_leading_zeros(Rest);
trim_leading_zeros(B) -> B.

%% RFC 7638 JWK thumbprint for an EC P-256 key. X and Y are the base64url
%% coordinate strings exactly as they appear in the JWK.
jwk_thumbprint(XB64, YB64) ->
    X = to_bin(XB64),
    Y = to_bin(YB64),
    Json = <<"{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"",
             X/binary, "\",\"y\":\"", Y/binary, "\"}">>,
    base64url_encode(crypto:hash(sha256, Json)).

%% In-memory DPoP jti replay cache. Returns true if the jti has been seen
%% (i.e. this is a replay), false if it is fresh (and records it).
dpop_jti_seen(Jti, Ttl) ->
    ensure_jti_table(),
    JtiB = to_bin(Jti),
    Now = erlang:system_time(second),
    catch ets:select_delete(gleam_pds_dpop_jti,
        [{{'_', '$1'}, [{'<', '$1', Now}], [true]}]),
    case ets:lookup(gleam_pds_dpop_jti, JtiB) of
        [] ->
            ets:insert(gleam_pds_dpop_jti, {JtiB, Now + Ttl}),
            false;
        _ ->
            true
    end.

ensure_jti_table() ->
    case ets:info(gleam_pds_dpop_jti, name) of
        undefined ->
            _ = spawn(fun jti_table_owner/0),
            wait_for_jti_table(200);
        _ ->
            ok
    end.

jti_table_owner() ->
    try ets:new(gleam_pds_dpop_jti, [set, public, named_table]) of
        _ -> jti_owner_loop()
    catch
        _:_ -> ok
    end.

jti_owner_loop() ->
    receive
        stop -> ok
    after 3600000 ->
        jti_owner_loop()
    end.

wait_for_jti_table(0) -> ok;
wait_for_jti_table(N) ->
    case ets:info(gleam_pds_dpop_jti, name) of
        undefined ->
            timer:sleep(1),
            wait_for_jti_table(N - 1);
        _ ->
            ok
    end.
