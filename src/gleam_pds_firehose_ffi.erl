-module(gleam_pds_firehose_ffi).
-export([make_commit_header/0, make_commit_body/12,
         make_account_header/0, make_account_body/4,
         make_identity_header/0, make_identity_body/4,
         make_sync_header/0, make_sync_body/5,
         make_info_header/0, make_info_body/2,
         collect_repo_blocks/3, commit_data_cid/3]).

%% ────────────────────────────────────────────────────────────────────────────
%% Frame header / body constructors
%% ────────────────────────────────────────────────────────────────────────────

%% #commit header: {"op": 1, "t": "#commit"}
make_commit_header() ->
    #{<<"op">> => 1, <<"t">> => <<"#commit">>}.

%% Build the body map for a #commit event.
%%   Since            - previous commit rev (binary), <<>> => null
%%   PrevDataCidBytes - previous MST root CID bytes, <<>> => null (prevData)
%%   OpsCidBytes      - new record CID bytes, <<>> => null (delete)
%%   OpsPrevCidBytes  - previous record CID bytes, <<>> => null (create)
make_commit_body(Seq, Did, Time, Rev, Since, CommitCidBytes, PrevDataCidBytes,
                 Blocks, OpsAction, OpsPath, OpsCidBytes, OpsPrevCidBytes) ->
    SinceVal = case Since of <<>> -> null; _ -> Since end,
    Op = #{<<"action">> => OpsAction,
           <<"path">> => OpsPath,
           <<"cid">> => maybe_link(OpsCidBytes),
           <<"prev">> => maybe_link(OpsPrevCidBytes)},
    #{<<"seq">> => Seq,
      <<"repo">> => Did,
      <<"time">> => Time,
      <<"rev">> => Rev,
      <<"since">> => SinceVal,
      <<"commit">> => cid_link(CommitCidBytes),
      <<"tooBig">> => false,
      <<"rebase">> => false,
      <<"blocks">> => {byte_string, Blocks},
      <<"ops">> => [Op],
      <<"prevData">> => maybe_link(PrevDataCidBytes),
      <<"blobs">> => []
    }.

%% #account header + body: { seq, did, time, active }
make_account_header() ->
    #{<<"op">> => 1, <<"t">> => <<"#account">>}.

make_account_body(Seq, Did, Time, Active) ->
    #{<<"seq">> => Seq,
      <<"did">> => Did,
      <<"time">> => Time,
      <<"active">> => Active}.

%% #identity header + body: { seq, did, time, handle? }
make_identity_header() ->
    #{<<"op">> => 1, <<"t">> => <<"#identity">>}.

make_identity_body(Seq, Did, Time, Handle) ->
    HandleVal = case Handle of <<>> -> null; _ -> Handle end,
    #{<<"seq">> => Seq,
      <<"did">> => Did,
      <<"time">> => Time,
      <<"handle">> => HandleVal}.

%% #sync header + body: { seq, did, blocks(CAR), rev, time }
make_sync_header() ->
    #{<<"op">> => 1, <<"t">> => <<"#sync">>}.

make_sync_body(Seq, Did, Time, Rev, Blocks) ->
    #{<<"seq">> => Seq,
      <<"did">> => Did,
      <<"time">> => Time,
      <<"rev">> => Rev,
      <<"blocks">> => {byte_string, Blocks}}.

%% #info header + body: { name, message }
make_info_header() ->
    #{<<"op">> => 1, <<"t">> => <<"#info">>}.

make_info_body(Name, Message) ->
    #{<<"name">> => Name, <<"message">> => Message}.

%% CID link helpers (DAG-CBOR tag 42 + 0x00 multibase prefix)
cid_link(CidBytes) ->
    {cbor_tag, 42, {byte_string, <<0, CidBytes/binary>>}}.

maybe_link(<<>>) -> null;
maybe_link(CidBytes) ->
    {cbor_tag, 42, {byte_string, <<0, CidBytes/binary>>}}.

%% ────────────────────────────────────────────────────────────────────────────
%% Reachability walk: gather the complete, importable block set for a commit.
%%
%% Starting from the commit block, follow the `data` link into the MST and walk
%% every reachable node (`l` left link, and each entry's `t` subtree + `v` value
%% leaf). Record leaf blocks are loaded from the `blocks` table when present, or
%% the `records` table as a fallback (legacy repos). Only reachable blocks are
%% returned, so there are no orphaned / superseded MST versions in the output.
%%
%% Returns a deduplicated list of {CidBytes, BlockData}.
%% ────────────────────────────────────────────────────────────────────────────

collect_repo_blocks(DB, Did, CommitCidStr) ->
    case load_block_opt(DB, Did, CommitCidStr) of
        undefined -> [];
        CommitCbor ->
            Acc0 = maps:put(CommitCidStr, CommitCbor, #{}),
            Acc1 = case decode_map(CommitCbor) of
                {ok, Map} -> walk_link(DB, Did, maps:get(<<"data">>, Map, null), Acc0);
                error -> Acc0
            end,
            maps:fold(
                fun(CidStr, Data, L) ->
                    [{gleam_pds_cbor_ffi:cid_bytes_from_base32(CidStr), Data} | L]
                end, [], Acc1)
    end.

%% Return the MST root (data) CID string of a commit, or <<>> when unavailable.
commit_data_cid(_DB, _Did, <<>>) -> <<>>;
commit_data_cid(DB, Did, CommitCidStr) ->
    case load_block_opt(DB, Did, CommitCidStr) of
        undefined -> <<>>;
        CommitCbor ->
            case decode_map(CommitCbor) of
                {ok, Map} ->
                    case maps:get(<<"data">>, Map, null) of
                        {cbor_tag, 42, {byte_string, <<0, CidBytes/binary>>}} ->
                            cid_to_str(CidBytes);
                        _ -> <<>>
                    end;
                error -> <<>>
            end
    end.

walk_link(DB, Did, {cbor_tag, 42, {byte_string, <<0, CidBytes/binary>>}}, Acc) ->
    CidStr = cid_to_str(CidBytes),
    case maps:is_key(CidStr, Acc) of
        true -> Acc;
        false ->
            case load_any(DB, Did, CidStr) of
                undefined -> Acc;
                Data ->
                    Acc1 = maps:put(CidStr, Data, Acc),
                    walk_children(DB, Did, Data, Acc1)
            end
    end;
walk_link(_DB, _Did, _, Acc) -> Acc.

%% Recurse into a block only if it looks like an MST node (has both `e` and `l`).
walk_children(DB, Did, Cbor, Acc) ->
    case decode_map(Cbor) of
        {ok, Map} ->
            case maps:is_key(<<"e">>, Map) andalso maps:is_key(<<"l">>, Map) of
                true ->
                    Acc1 = walk_link(DB, Did, maps:get(<<"l">>, Map, null), Acc),
                    Entries = maps:get(<<"e">>, Map, []),
                    lists:foldl(
                        fun(E, A) when is_map(E) ->
                                A1 = walk_link(DB, Did, maps:get(<<"v">>, E, null), A),
                                walk_link(DB, Did, maps:get(<<"t">>, E, null), A1);
                           (_, A) -> A
                        end, Acc1, Entries);
                false -> Acc
            end;
        error -> Acc
    end.

decode_map(Cbor) ->
    case catch gleam_pds_cbor_ffi:decode_cbor(Cbor) of
        {Map, _} when is_map(Map) -> {ok, Map};
        _ -> error
    end.

load_any(DB, Did, CidStr) ->
    case load_block_opt(DB, Did, CidStr) of
        undefined -> load_record_opt(DB, Did, CidStr);
        Data -> Data
    end.

%% DB access goes through the Gleam module gleam_pds@db (which owns the sqlight
%% connection); esqlite3 cannot be called directly on a sqlight connection.
load_block_opt(DB, Did, CidStr) ->
    case gleam_pds@db:ffi_get_block(DB, CidStr, Did) of
        {ok, Data} when is_binary(Data) -> Data;
        _ -> undefined
    end.

load_record_opt(DB, Did, CidStr) ->
    case gleam_pds@db:ffi_get_record_cbor(DB, CidStr, Did) of
        {ok, Data} when is_binary(Data) -> Data;
        _ -> undefined
    end.

cid_to_str(CidBytes) ->
    B32 = string:lowercase(gleam_pds_crypto_ffi:base32_encode(CidBytes)),
    iolist_to_binary([<<"b">>, B32]).
