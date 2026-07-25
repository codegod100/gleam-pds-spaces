%% gleam_pds_mst_ffi.erl
%% Incremental Merkle Search Tree implementation for AT Protocol.
%%
%% Instead of recomputing the entire tree from all records on every write
%% (O(n)), this module maintains the MST node blocks in a `blocks` table
%% and only touches the O(log n) nodes on the affected path.
%%
%% Public API (called from Gleam via @external FFI):
%%   init_repo_mst/2   - initialise an empty MST for a new repo
%%   mst_upsert/4      - insert or update a key in the MST, returns new root CID string
%%   mst_delete/3      - delete a key from the MST, returns new root CID string
%%   mst_commit/4      - sign a commit over the current MST root, persist to repos table
%%   sign_and_store_commit/5

-module(gleam_pds_mst_ffi).
-export([init_repo_mst/2, mst_upsert/4, mst_delete/3, sign_and_store_commit/5]).

%% ────────────────────────────────────────────────────────────────────────────
%% Public API
%% ────────────────────────────────────────────────────────────────────────────

%% Initialise an empty MST for a newly created repo.
%% Stores the empty root block in the `blocks` table and returns the root CID string.
init_repo_mst(DB, Did) ->
    RootCbor = empty_node_cbor(),
    RootCidBytes = compute_cid_bytes(RootCbor),
    RootCidStr = cid_to_str(RootCidBytes),
    store_block(DB, Did, RootCidStr, RootCbor),
    RootCidStr.

%% Insert or update `Key` -> `ValueCidStr` in the MST rooted at the repo head.
%% Returns the new root CID string (base32 encoded).
%%
%% Strategy (correctness over incrementality): load every leaf key -> value CID
%% pair currently in the tree, apply the change to that flat list, then rebuild
%% the whole tree through the single canonical builder in gleam_pds_cbor_ffi. This
%% guarantees byte-identical roots to the from-scratch CAR export path.
mst_upsert(DB, Did, Key, ValueCidStr) ->
    ValueCidBytes = gleam_pds_cbor_ffi:cid_bytes_from_base32(ValueCidStr),
    Entries0 = load_all_entries(DB, Did),
    Entries = lists:keystore(Key, 1, Entries0, {Key, ValueCidBytes}),
    rebuild_and_store(DB, Did, Entries).

%% Delete `Key` from the MST. Returns the new root CID string.
mst_delete(DB, Did, Key) ->
    Entries0 = load_all_entries(DB, Did),
    Entries = lists:keydelete(Key, 1, Entries0),
    rebuild_and_store(DB, Did, Entries).

%% Rebuild the entire MST from a flat [{Key, ValueCidBytes}] list, persist all
%% node blocks, and return the new root CID string.
rebuild_and_store(DB, Did, Entries) ->
    {RootCidBytes, Blocks} = gleam_pds_cbor_ffi:build_mst_from_entries(Entries),
    lists:foreach(fun({CidBytes, Cbor}) ->
        store_block(DB, Did, cid_to_str(CidBytes), Cbor)
    end, Blocks),
    cid_to_str(RootCidBytes).

%% Load every leaf {FullKey, ValueCidBytes} pair from the current MST, in order.
load_all_entries(DB, Did) ->
    RootCidStr = load_current_mst_root(DB, Did),
    RootCbor = load_block(DB, Did, RootCidStr),
    collect_node(DB, Did, RootCbor).

%% In-order traversal of an MST node: left subtree, then for each entry the leaf
%% itself followed by its right (t) subtree.
collect_node(DB, Did, NodeCbor) ->
    {LeftLink, Entries} = decode_node(NodeCbor),
    collect_subtree(DB, Did, LeftLink) ++ collect_entries(DB, Did, Entries, <<>>).

collect_subtree(_DB, _Did, null) -> [];
collect_subtree(DB, Did, {cbor_tag, 42, {byte_string, <<0, CidBytes/binary>>}}) ->
    CidStr = cid_to_str(CidBytes),
    Cbor = load_block(DB, Did, CidStr),
    collect_node(DB, Did, Cbor);
collect_subtree(_DB, _Did, _) -> [].

collect_entries(_DB, _Did, [], _PrevKey) -> [];
collect_entries(DB, Did, [E | Rest], PrevKey) ->
    FullKey = reconstruct_key(E, PrevKey),
    ValueBytes = value_cid_bytes(maps:get(<<"v">>, E, null)),
    TreeKVs = collect_subtree(DB, Did, maps:get(<<"t">>, E, null)),
    [{FullKey, ValueBytes}] ++ TreeKVs
        ++ collect_entries(DB, Did, Rest, FullKey).

%% Build and sign a commit on top of the current MST root.
%% Persists the new `head` and `rev` in the `repos` table.
%% Returns the commit CID string.
sign_and_store_commit(DB, Did, Rev, RootCidStr, PrivateKey) ->
    %% Sign over the MST root that the caller (mst_upsert/mst_delete) just
    %% produced. The repo `head` column stores the previous *commit* CID, so we
    %% must not read it here as if it were the MST root. Fall back to resolving
    %% the current MST root from the stored commit only when no root was passed.
    MstRootStr = case RootCidStr of
        <<_, _/binary>> -> RootCidStr;
        _ -> load_current_mst_root(DB, Did)
    end,
    RootCidBytes = gleam_pds_cbor_ffi:cid_bytes_from_base32(MstRootStr),
    MstLink = {cbor_tag, 42, {byte_string, <<0, RootCidBytes/binary>>}},
    %% Sign over the DAG-CBOR of the sig-LESS commit map (no sig key at all).
    UnsignedCommit = #{<<"did">> => Did, <<"version">> => 3,
                       <<"data">> => MstLink, <<"rev">> => Rev,
                       <<"prev">> => null},
    UnsignedCbor = gleam_pds_cbor_ffi:encode(UnsignedCommit),
    Sig = sign_commit(UnsignedCbor, PrivateKey),
    SignedCommit = #{<<"did">> => Did, <<"version">> => 3,
                     <<"data">> => MstLink, <<"rev">> => Rev,
                     <<"prev">> => null, <<"sig">> => {byte_string, Sig}},
    CommitCbor = gleam_pds_cbor_ffi:encode(SignedCommit),
    CommitCidBytes = compute_cid_bytes(CommitCbor),
    CommitCidStr = cid_to_str(CommitCidBytes),
    %% Persist commit block and update repo head
    store_block(DB, Did, CommitCidStr, CommitCbor),
    update_repo_head(DB, Did, CommitCidStr, Rev),
    CommitCidStr.

%% ────────────────────────────────────────────────────────────────────────────
%% Node encoding / decoding helpers
%% ────────────────────────────────────────────────────────────────────────────

empty_node_cbor() ->
    gleam_pds_cbor_ffi:encode(#{<<"e">> => [], <<"l">> => null}).

decode_node(Cbor) ->
    {Map, _} = gleam_pds_cbor_ffi:decode_cbor(Cbor),
    LeftLink = maps:get(<<"l">>, Map, null),
    Entries = maps:get(<<"e">>, Map, []),
    {LeftLink, Entries}.

%% Reconstruct the full key for an entry given the previous key.
reconstruct_key(Entry, PrevKey) ->
    P = maps:get(<<"p">>, Entry, 0),
    KSuffix = case maps:get(<<"k">>, Entry, <<>>) of
        {byte_string, B} -> B;
        B when is_binary(B) -> B;
        _ -> <<>>
    end,
    Prefix = binary:part(PrevKey, 0, min(P, byte_size(PrevKey))),
    <<Prefix/binary, KSuffix/binary>>.

value_cid_bytes({cbor_tag, 42, {byte_string, <<0, Bytes/binary>>}}) -> Bytes;
value_cid_bytes(_) -> <<>>.

%% ────────────────────────────────────────────────────────────────────────────
%% CID helpers
%% ────────────────────────────────────────────────────────────────────────────

compute_cid_bytes(CborData) ->
    Hash = crypto:hash(sha256, CborData),
    <<1, 16#71, 16#12, 32, Hash/binary>>.

cid_to_str(CidBytes) ->
    B32 = string:lowercase(gleam_pds_crypto_ffi:base32_encode(CidBytes)),
    iolist_to_binary([<<"b">>, B32]).

%% ────────────────────────────────────────────────────────────────────────────
%% Signing
%% ────────────────────────────────────────────────────────────────────────────

%% secp256r1 / P-256 curve order.
-define(P256_N, 16#FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551).

sign_commit(UnsignedCbor, PrivateKey) when byte_size(PrivateKey) > 0 ->
    DerSig = crypto:sign(ecdsa, sha256, UnsignedCbor, [PrivateKey, secp256r1]),
    <<16#30, _Len, 16#02, RLen, RBin:RLen/binary, 16#02, SLen, SBin:SLen/binary, _/binary>> = DerSig,
    R = binary:decode_unsigned(RBin),
    S0 = binary:decode_unsigned(SBin),
    S = normalize_low_s(S0),
    <<R:256, S:256>>;
sign_commit(_, _) -> <<0:512>>.

%% Enforce low-S: if S is in the upper half of the curve order, replace with n - S.
normalize_low_s(S) when S > (?P256_N div 2) -> ?P256_N - S;
normalize_low_s(S) -> S.

%% ────────────────────────────────────────────────────────────────────────────
%% SQLite helpers
%%
%% DB access goes through the Gleam module gleam_pds@db (which owns the sqlight
%% connection). We cannot call esqlite3 directly here: sqlight wraps the
%% connection as an opaque {esqlite3, Ref} term that esqlite3:q/prepare reject.
%% ────────────────────────────────────────────────────────────────────────────

%% Resolve the current MST root CID string for a repo.
%%
%% The repo `head` column stores the latest *commit* CID (this is the
%% convention the rest of the codebase relies on, e.g. sync.gleam). The MST
%% root is the commit's `data` field, so we load the commit block and extract
%% it. If there is no head yet (brand new repo) we initialise an empty MST.
%% As a defensive fallback, if the head block is already an MST node (has no
%% `data` field) we treat the head itself as the root.
load_current_mst_root(DB, Did) ->
    case query_repo_head(DB, Did) of
        {ok, HeadCidStr} ->
            Cbor = load_block(DB, Did, HeadCidStr),
            {Term, _} = gleam_pds_cbor_ffi:decode_cbor(Cbor),
            case Term of
                #{<<"data">> := {cbor_tag, 42, {byte_string, <<0, MstBytes/binary>>}}} ->
                    cid_to_str(MstBytes);
                _ ->
                    HeadCidStr
            end;
        error ->
            init_repo_mst(DB, Did)
    end.

query_repo_head(DB, Did) ->
    case gleam_pds@db:ffi_get_repo_head(DB, Did) of
        {ok, Head} when is_binary(Head), byte_size(Head) > 0 -> {ok, Head};
        _ -> error
    end.

load_block(DB, Did, CidStr) ->
    case gleam_pds@db:ffi_get_block(DB, CidStr, Did) of
        {ok, Data} when is_binary(Data) -> Data;
        _ -> empty_node_cbor()
    end.

store_block(DB, Did, CidStr, Data) ->
    gleam_pds@db:ffi_put_block(DB, CidStr, Did, Data).

update_repo_head(DB, Did, HeadCidStr, Rev) ->
    gleam_pds@db:ffi_set_repo_head(DB, Did, HeadCidStr, Rev).
