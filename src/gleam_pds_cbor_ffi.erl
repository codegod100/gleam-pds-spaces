-module(gleam_pds_cbor_ffi).
-export([encode/1, decode_cbor/1, encode_header_and_body/2, build_car_file/2, build_repo_car/4, compute_repo_commit_cid/4, cid_bytes_from_base32/1, encode_record_cbor/1, json_to_cbor/1, cbor_to_json/1, build_mst_from_entries/1]).


%% Encode an Erlang term to DAG-CBOR binary.
%% Supports: maps, strings (binaries), integers, lists, booleans, null/nil,
%%           and tagged CID links {cbor_tag, 42, Bytes}.
encode(Term) ->
    iolist_to_binary(encode_term(Term)).

encode_term(null) -> encode_simple(22);  % CBOR null
encode_term(nil) -> encode_simple(22);
encode_term(true) -> encode_simple(21);  % CBOR true
encode_term(false) -> encode_simple(20); % CBOR false
encode_term(N) when is_integer(N), N >= 0 ->
    encode_unsigned(0, N);
encode_term(N) when is_integer(N), N < 0 ->
    encode_unsigned(1, -1 - N);
encode_term(Bin) when is_binary(Bin) ->
    %% UTF-8 text string (major type 3)
    [encode_unsigned(3, byte_size(Bin)), Bin];
encode_term({byte_string, Bin}) when is_binary(Bin) ->
    %% Byte string (major type 2)
    [encode_unsigned(2, byte_size(Bin)), Bin];
encode_term({cbor_tag, Tag, Value}) ->
    %% CBOR tag
    [encode_unsigned(6, Tag), encode_term(Value)];
encode_term(List) when is_list(List) ->
    %% Array (major type 4)
    Len = length(List),
    [encode_unsigned(4, Len) | [encode_term(E) || E <- List]];
encode_term(Map) when is_map(Map) ->
    %% DAG-CBOR requires map keys sorted by encoded byte length, then lexicographically.
    %% For simplicity, we sort keys as strings.
    Pairs = maps:to_list(Map),
    %% DAG-CBOR: sort by the CBOR-encoded key bytes (length-first)
    SortedPairs = lists:sort(fun({K1, _}, {K2, _}) ->
        E1 = iolist_to_binary(encode_term(K1)),
        E2 = iolist_to_binary(encode_term(K2)),
        E1 =< E2
    end, Pairs),
    Len = length(SortedPairs),
    [encode_unsigned(5, Len) | lists:flatmap(fun({K, V}) ->
        [encode_term(K), encode_term(V)]
    end, SortedPairs)];
encode_term(_) ->
    encode_simple(22). % fallback to null

encode_unsigned(Major, N) when N < 24 ->
    <<((Major bsl 5) bor N)>>;
encode_unsigned(Major, N) when N < 256 ->
    <<((Major bsl 5) bor 24), N:8>>;
encode_unsigned(Major, N) when N < 65536 ->
    <<((Major bsl 5) bor 25), N:16>>;
encode_unsigned(Major, N) when N < 4294967296 ->
    <<((Major bsl 5) bor 26), N:32>>;
encode_unsigned(Major, N) ->
    <<((Major bsl 5) bor 27), N:64>>.

encode_simple(Value) ->
    <<((7 bsl 5) bor Value)>>.

%% Encode a firehose frame: header CBOR ++ body CBOR concatenated.
encode_header_and_body(Header, Body) ->
    H = encode(Header),
    B = encode(Body),
    <<H/binary, B/binary>>.

%% Build a minimal CAR v1 file from a list of {CidBytes, BlockData} pairs
%% and a root CID bytes.
%% CAR format:
%%   varint(header_len) + DAG-CBOR({"version":1, "roots":[root_cid_as_tag42]})
%%   for each block: varint(cid_len + data_len) + cid_bytes + data
build_car_file(RootCidBytes, Blocks) ->
    %% Build the header
    %% The roots in CAR are raw CID bytes (not CBOR-tagged), but the header itself is DAG-CBOR
    %% In CAR v1 header: {"version": 1, "roots": [CID]}
    %% CID in DAG-CBOR is tag 42 + byte string of (0x00 ++ cid_bytes)
    CidLink = {cbor_tag, 42, {byte_string, <<0, RootCidBytes/binary>>}},
    HeaderCbor = encode(#{<<"version">> => 1, <<"roots">> => [CidLink]}),
    HeaderLen = byte_size(HeaderCbor),
    HeaderVarInt = encode_varint(HeaderLen),
    
    %% Build block entries
    BlockEntries = lists:map(fun({CidBytes, Data}) ->
        EntryLen = byte_size(CidBytes) + byte_size(Data),
        EntryVarInt = encode_varint(EntryLen),
        <<EntryVarInt/binary, CidBytes/binary, Data/binary>>
    end, Blocks),
    
    iolist_to_binary([HeaderVarInt, HeaderCbor | BlockEntries]).

%% Unsigned LEB128 varint encoding
encode_varint(N) when N < 128 ->
    <<N>>;
encode_varint(N) ->
    <<((N band 127) bor 128), (encode_varint(N bsr 7))/binary>>.

%% Encode the "record" field from a dynamic request body to DAG-CBOR.
%% Takes the raw Erlang map from the decoded JSON body.
encode_record_cbor(Body) when is_map(Body) ->
    Record = case maps:find(<<"record">>, Body) of
        {ok, R} -> R;
        error -> Body
    end,
    encode(Record);
encode_record_cbor(_) -> encode(#{}).

%% Parse a JSON string and encode it as DAG-CBOR.
json_to_cbor(JsonBin) when is_binary(JsonBin) ->
    case json:decode(JsonBin) of
        Term -> encode(Term)
    end;
json_to_cbor(_) -> encode(#{}).

%% Build a proper AT Protocol repo CAR file with commit + MST + records.
%% Records: list of {Path, CborData} where Path is <<"collection/rkey">>
%% PrivateKey: the repo signing key (DER-encoded P-256 private key)
%% Did: the repo DID string
%% Rev: the revision TID string
build_repo_car(Did, Rev, Records, PrivateKey) ->
    %% 1. Build record blocks and collect CID mappings
    RecordBlocks = lists:map(fun({Path, CborData}) ->
        CidBytes = compute_cid_bytes(CborData),
        {Path, CidBytes, CborData}
    end, Records),

    %% 2. Sort records by path
    Sorted = lists:sort(fun({P1,_,_}, {P2,_,_}) -> P1 =< P2 end, RecordBlocks),

    %% 3. Build proper MST tree
    %% Annotate each entry with its depth
    Annotated = [{Path, CidBytes, compute_key_depth(Path)} || {Path, CidBytes, _} <- Sorted],

    %% Build tree recursively, collecting all MST node blocks
    {MstCidBytes, MstBlocks} = build_mst_node(Annotated),

    %% 4. Build unsigned commit object (NO sig field – signature is computed
    %%    over the DAG-CBOR of the sig-less map).
    MstLink = {cbor_tag, 42, {byte_string, <<0, MstCidBytes/binary>>}},
    UnsignedCommit = #{<<"did">> => Did,
                       <<"version">> => 3,
                       <<"data">> => MstLink,
                       <<"rev">> => Rev,
                       <<"prev">> => null},
    UnsignedCbor = encode(UnsignedCommit),

    %% 5. Sign the commit
    Sig = sign_commit(UnsignedCbor, PrivateKey),

    SignedCommit = #{<<"did">> => Did,
                     <<"version">> => 3,
                     <<"data">> => MstLink,
                     <<"rev">> => Rev,
                     <<"prev">> => null,
                     <<"sig">> => {byte_string, Sig}},
    CommitCbor = encode(SignedCommit),
    CommitCidBytes = compute_cid_bytes(CommitCbor),

    %% 6. Assemble CAR file: header + commit block + MST blocks + record blocks
    CommitLink = {cbor_tag, 42, {byte_string, <<0, CommitCidBytes/binary>>}},
    HeaderCbor = encode(#{<<"version">> => 1, <<"roots">> => [CommitLink]}),
    HeaderLen = byte_size(HeaderCbor),
    HeaderVarInt = encode_varint(HeaderLen),

    AllBlocks = [{CommitCidBytes, CommitCbor}] ++ MstBlocks ++
                [{Cid, Data} || {_, Cid, Data} <- RecordBlocks],

    BlockEntries = lists:map(fun({Cid, Data}) ->
        EntryLen = byte_size(Cid) + byte_size(Data),
        EntryVarInt = encode_varint(EntryLen),
        <<EntryVarInt/binary, Cid/binary, Data/binary>>
    end, AllBlocks),

    iolist_to_binary([HeaderVarInt, HeaderCbor | BlockEntries]).

%% Calculate the Base32-encoded real commit CID for a repository.
compute_repo_commit_cid(Did, Rev, Records, PrivateKey) ->
    RecordBlocks = lists:map(fun({Path, CborData}) ->
        CidBytes = compute_cid_bytes(CborData),
        {Path, CidBytes, CborData}
    end, Records),
    Sorted = lists:sort(fun({P1,_,_}, {P2,_,_}) -> P1 =< P2 end, RecordBlocks),
    Annotated = [{Path, CidBytes, compute_key_depth(Path)} || {Path, CidBytes, _} <- Sorted],
    {MstCidBytes, _} = build_mst_node(Annotated),
    MstLink = {cbor_tag, 42, {byte_string, <<0, MstCidBytes/binary>>}},
    UnsignedCommit = #{<<"did">> => Did,
                       <<"version">> => 3,
                       <<"data">> => MstLink,
                       <<"rev">> => Rev,
                       <<"prev">> => null},
    UnsignedCbor = encode(UnsignedCommit),
    Sig = sign_commit(UnsignedCbor, PrivateKey),
    SignedCommit = #{<<"did">> => Did,
                     <<"version">> => 3,
                     <<"data">> => MstLink,
                     <<"rev">> => Rev,
                     <<"prev">> => null,
                     <<"sig">> => {byte_string, Sig}},
    CommitCbor = encode(SignedCommit),
    CommitCidBytes = compute_cid_bytes(CommitCbor),
    Base32Encoded = string:lowercase(gleam_pds_crypto_ffi:base32_encode(CommitCidBytes)),
    iolist_to_binary([<<"b">>, Base32Encoded]).

%% Compute MST depth for a key: SHA-256 hash, count leading zero bits / 2
compute_key_depth(Key) ->
    Hash = crypto:hash(sha256, Key),
    count_leading_zeros(Hash, 0) div 2.

count_leading_zeros(<<>>, Acc) -> Acc;
count_leading_zeros(<<0:1, Rest/bitstring>>, Acc) ->
    count_leading_zeros(Rest, Acc + 1);
count_leading_zeros(_, Acc) -> Acc.

%% Canonical MST builder shared by the batch (CAR export) path and the
%% incremental (gleam_pds_mst_ffi) path so the two can never diverge.
%% Input: a list of {Key :: binary(), ValueCidBytes :: binary()} pairs.
%% Output: {RootCidBytes, AllBlocks} where AllBlocks is [{CidBytes, CborData}, ...]
%% (root block included). Keys are sorted and layer-annotated internally.
build_mst_from_entries(KVList) ->
    Sorted = lists:sort(fun({K1, _}, {K2, _}) -> K1 =< K2 end, KVList),
    Annotated = [{Key, CidBytes, compute_key_depth(Key)}
                 || {Key, CidBytes} <- Sorted],
    build_mst_node(Annotated).

%% Build an MST node from a sorted list of {Path, CidBytes, Depth} entries.
%% Returns {NodeCidBytes, AllBlocks} where AllBlocks is [{CidBytes, CborData}, ...]
build_mst_node([]) ->
    NodeCbor = encode(#{<<"e">> => [], <<"l">> => null}),
    NodeCid = compute_cid_bytes(NodeCbor),
    {NodeCid, [{NodeCid, NodeCbor}]};
build_mst_node(Entries) ->
    MaxDepth = lists:max([D || {_, _, D} <- Entries]),
    build_mst_at_depth(Entries, MaxDepth).

%% Build an MST node at a given depth layer.
%% Entries at this depth go into the node. Entries below go into subtree nodes.
%% The "l" (left) field links to a subtree of entries before the first entry at this depth.
%% Each entry's "t" (tree) field links to a subtree of entries between it and the next entry.
build_mst_at_depth(Entries, Depth) ->
    %% Split into: leading lower-depth entries, then alternating [ThisDepthEntry, LowerEntries...]
    {LeadingLower, AtDepth} = split_leading_lower(Entries, Depth),

    %% Build the left subtree from leading lower entries
    {LeftLink, LeftBlocks} = case LeadingLower of
        [] -> {null, []};
        _ ->
            {LCid, LBlocks} = build_mst_node(LeadingLower),
            {{cbor_tag, 42, {byte_string, <<0, LCid/binary>>}}, LBlocks}
    end,

    %% Process entries at this depth, each followed by trailing lower entries
    {NodeEntries, RightBlocks} = build_entries_with_subtrees(AtDepth, Depth, <<>>),

    NodeCbor = encode(#{<<"e">> => NodeEntries, <<"l">> => LeftLink}),
    NodeCid = compute_cid_bytes(NodeCbor),
    {NodeCid, [{NodeCid, NodeCbor}] ++ LeftBlocks ++ RightBlocks}.

%% Split off leading entries with depth < Depth.
%% Returns {LeadingLower, Rest} where Rest starts with an entry at Depth (or is empty).
split_leading_lower([], _Depth) -> {[], []};
split_leading_lower([{_P, _C, D} = E | Rest], Depth) when D < Depth ->
    {More, Remaining} = split_leading_lower(Rest, Depth),
    {[E | More], Remaining};
split_leading_lower(Entries, _Depth) -> {[], Entries}.

%% Process a list starting with entries at Depth.
%% For each entry at Depth, collect trailing lower-depth entries as its right subtree.
%% Returns {[NodeEntry, ...], AllSubBlocks}
build_entries_with_subtrees([], _Depth, _PrevKey) -> {[], []};
build_entries_with_subtrees([{Path, CidBytes, _D} | Rest], Depth, PrevKey) ->
    %% Collect trailing lower-depth entries (this entry's right subtree)
    {TrailingLower, Remaining} = split_leading_lower(Rest, Depth),

    %% Build right subtree
    {TreeLink, TreeBlocks} = case TrailingLower of
        [] -> {null, []};
        _ ->
            {TCid, TBlocks} = build_mst_node(TrailingLower),
            {{cbor_tag, 42, {byte_string, <<0, TCid/binary>>}}, TBlocks}
    end,

    %% Build this entry
    PrefixLen = shared_prefix_len(PrevKey, Path),
    KeySuffix = binary:part(Path, PrefixLen, byte_size(Path) - PrefixLen),
    CidLink = {cbor_tag, 42, {byte_string, <<0, CidBytes/binary>>}},
    Entry = #{<<"k">> => {byte_string, KeySuffix},
              <<"p">> => PrefixLen,
              <<"t">> => TreeLink,
              <<"v">> => CidLink},

    %% Recurse for remaining entries
    {MoreEntries, MoreBlocks} = build_entries_with_subtrees(Remaining, Depth, Path),
    {[Entry | MoreEntries], TreeBlocks ++ MoreBlocks}.

compute_cid_bytes(CborData) ->
    Hash = crypto:hash(sha256, CborData),
    <<1, 16#71, 16#12, 32, Hash/binary>>.

shared_prefix_len(<<A, RestA/binary>>, <<A, RestB/binary>>) ->
    1 + shared_prefix_len(RestA, RestB);
shared_prefix_len(_, _) -> 0.

sign_commit(UnsignedCbor, PrivateKey) when byte_size(PrivateKey) > 0 ->
    %% Sign with ES256 using crypto module (same as sign_es256 in crypto FFI)
    DerSig = crypto:sign(ecdsa, sha256, UnsignedCbor, [PrivateKey, secp256r1]),
    %% Convert DER signature to raw R||S (32 bytes each), low-S normalized.
    <<16#30, _Len, 16#02, RLen, RBin:RLen/binary, 16#02, SLen, SBin:SLen/binary, _/binary>> = DerSig,
    R = binary:decode_unsigned(RBin),
    S0 = binary:decode_unsigned(SBin),
    S = normalize_low_s(S0),
    <<R:256, S:256>>;
sign_commit(_, _) ->
    %% No key available, return empty sig
    <<0:512>>.

%% secp256r1 / P-256 curve order.
-define(P256_N, 16#FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551).

%% Enforce low-S: if S is in the upper half of the curve order, replace with n - S.
normalize_low_s(S) when S > (?P256_N div 2) -> ?P256_N - S;
normalize_low_s(S) -> S.

%% Decode DAG-CBOR binary to a JSON string.
cbor_to_json(CborBin) when is_binary(CborBin) ->
    {Term, _Rest} = decode_cbor(CborBin),
    json_encode(Term);
cbor_to_json(_) -> <<"{}">>.

%% Decode one CBOR value, return {Value, RestBinary}
decode_cbor(<<First, Rest/binary>>) ->
    Major = First bsr 5,
    Info = First band 16#1f,
    case Major of
        0 -> %% unsigned int
            {N, R} = decode_int(Info, Rest),
            {N, R};
        1 -> %% negative int
            {N, R} = decode_int(Info, Rest),
            {-1 - N, R};
        2 -> %% byte string
            {Len, R} = decode_int(Info, Rest),
            <<Bytes:Len/binary, R2/binary>> = R,
            {{byte_string, Bytes}, R2};
        3 -> %% text string
            {Len, R} = decode_int(Info, Rest),
            <<Str:Len/binary, R2/binary>> = R,
            {Str, R2};
        4 -> %% array
            {Len, R} = decode_int(Info, Rest),
            decode_array(Len, R, []);
        5 -> %% map
            {Len, R} = decode_int(Info, Rest),
            decode_map(Len, R, #{});
        6 -> %% tag
            {Tag, R} = decode_int(Info, Rest),
            %% Preserve the tag so re-encoding round-trips (e.g. tag 42 CID links).
            {Inner, R2} = decode_cbor(R),
            {{cbor_tag, Tag, Inner}, R2};
        7 -> %% simple/float
            case Info of
                20 -> {false, Rest};
                21 -> {true, Rest};
                22 -> {null, Rest};
                23 -> {undefined, Rest};
                25 -> %% float16
                    <<_F:16, R/binary>> = Rest,
                    {0.0, R};
                26 -> %% float32
                    <<F:32/float, R/binary>> = Rest,
                    {F, R};
                27 -> %% float64
                    <<F:64/float, R/binary>> = Rest,
                    {F, R};
                _ -> {null, Rest}
            end
    end;
decode_cbor(<<>>) -> {null, <<>>}.

decode_int(Info, Rest) when Info < 24 -> {Info, Rest};
decode_int(24, <<V, R/binary>>) -> {V, R};
decode_int(25, <<V:16, R/binary>>) -> {V, R};
decode_int(26, <<V:32, R/binary>>) -> {V, R};
decode_int(27, <<V:64, R/binary>>) -> {V, R}.

decode_array(0, Rest, Acc) -> {lists:reverse(Acc), Rest};
decode_array(N, Bin, Acc) ->
    {Val, Rest} = decode_cbor(Bin),
    decode_array(N - 1, Rest, [Val | Acc]).

decode_map(0, Rest, Acc) -> {Acc, Rest};
decode_map(N, Bin, Acc) ->
    {Key, R1} = decode_cbor(Bin),
    {Val, R2} = decode_cbor(R1),
    decode_map(N - 1, R2, maps:put(Key, Val, Acc)).

%% Encode an Erlang term to JSON binary
json_encode(null) -> <<"null">>;
json_encode(undefined) -> <<"null">>;
json_encode(nil) -> <<"null">>;
json_encode(true) -> <<"true">>;
json_encode(false) -> <<"false">>;
json_encode(N) when is_integer(N) -> integer_to_binary(N);
json_encode(N) when is_float(N) -> float_to_binary(N, [{decimals, 10}, compact]);
json_encode(Bin) when is_binary(Bin) -> <<"\"" , (json_escape(Bin))/binary, "\"">>;
json_encode({cbor_tag, 42, {byte_string, <<0, CidBytes/binary>>}}) ->
    %% CID link (tag 42): encode as {"$link": "b<base32>"}
    B32 = string:lowercase(gleam_pds_crypto_ffi:base32_encode(CidBytes)),
    iolist_to_binary([<<"{\"$link\":\"b">>, B32, <<"\"}">>]);
json_encode({cbor_tag, _Tag, Value}) ->
    json_encode(Value);
json_encode({byte_string, _Bytes}) ->
    %% Raw byte strings have no direct JSON representation here.
    <<"null">>;
json_encode(List) when is_list(List) ->
    Elements = lists:join(<<",">>, [json_encode(E) || E <- List]),
    iolist_to_binary([<<"[">>, Elements, <<"]">>]);
json_encode(Map) when is_map(Map) ->
    %% Sort keys for deterministic output
    Pairs = lists:sort(maps:to_list(Map)),
    Elements = lists:join(<<",">>, [
        iolist_to_binary([<<"\"">>, json_escape(K), <<"\":">>, json_encode(V)])
        || {K, V} <- Pairs, is_binary(K)
    ]),
    iolist_to_binary([<<"{">>, Elements, <<"}">>]);
json_encode(_) -> <<"null">>.

json_escape(Bin) ->
    binary:replace(
        binary:replace(
            binary:replace(
                binary:replace(Bin, <<"\\">>, <<"\\\\">>, [global]),
                <<"\"">>, <<"\\\"">>, [global]),
            <<"\n">>, <<"\\n">>, [global]),
        <<"\r">>, <<"\\r">>, [global]).

%% Decode a base32 CID string (with 'b' prefix) to raw CID bytes
%% CIDv1 base32lower: 'b' + base32lower(cid_bytes)
cid_bytes_from_base32(<<"b", Rest/binary>>) ->
    try
        base32_decode(Rest)
    catch
        _:_ -> <<>>
    end;
cid_bytes_from_base32(_) -> <<>>.

%% RFC 4648 base32 decode (lowercase input)
%% Alphabet: abcdefghijklmnopqrstuvwxyz234567
base32_decode(Bin) ->
    Bits = << <<(base32_char_to_val(C)):5>> || <<C>> <= Bin >>,
    %% Trim to whole bytes
    BitLen = bit_size(Bits),
    ByteLen = BitLen div 8,
    <<Result:ByteLen/binary, _/bitstring>> = Bits,
    Result.

base32_char_to_val(C) when C >= $a, C =< $z -> C - $a;
base32_char_to_val(C) when C >= $2, C =< $7 -> C - $2 + 26;
base32_char_to_val(C) when C >= $A, C =< $Z -> C - $A;  %% handle uppercase too
base32_char_to_val($=) -> 0.  %% padding
