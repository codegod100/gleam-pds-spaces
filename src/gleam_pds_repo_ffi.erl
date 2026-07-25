-module(gleam_pds_repo_ffi).
-export([extract_record_json/1, extract_writes/1]).

%% Extract the "record" field from a decoded JSON dynamic value
%% and re-encode it as a JSON string.
extract_record_json(Body) ->
    try
        case Body of
            Map when is_map(Map) ->
                case maps:find(<<"record">>, Map) of
                    {ok, Record} ->
                        encode_json(Record);
                    error ->
                        %% No record field, encode the whole thing
                        encode_json(Map)
                end;
            _ ->
                <<"{}">>
        end
    catch
        _:_ -> <<"{}">>
    end.

encode_json(null) -> <<"null">>;
encode_json(nil) -> <<"null">>;
encode_json(true) -> <<"true">>;
encode_json(false) -> <<"false">>;
encode_json(N) when is_integer(N) -> integer_to_binary(N);
encode_json(N) when is_float(N) -> float_to_binary(N, [{decimals, 10}, compact]);
encode_json(Bin) when is_binary(Bin) -> <<"\"", (escape_json_string(Bin))/binary, "\"">>;
encode_json(List) when is_list(List) ->
    Elements = lists:join(<<",">>, [encode_json(E) || E <- List]),
    iolist_to_binary([<<"[">>, Elements, <<"]">>]);
encode_json(Map) when is_map(Map) ->
    Pairs = maps:fold(fun(K, V, Acc) ->
        Key = if is_binary(K) -> K;
                 is_atom(K) -> atom_to_binary(K, utf8);
                 true -> iolist_to_binary(io_lib:format("~p", [K]))
              end,
        [<<"\"", (escape_json_string(Key))/binary, "\":", (encode_json(V))/binary>> | Acc]
    end, [], Map),
    iolist_to_binary([<<"{">>, lists:join(<<",">>, lists:reverse(Pairs)), <<"}">>]);
encode_json(Atom) when is_atom(Atom) ->
    <<"\"", (atom_to_binary(Atom, utf8))/binary, "\"">>;
encode_json(_) -> <<"null">>.

escape_json_string(Bin) ->
    binary:replace(
        binary:replace(
            binary:replace(
                binary:replace(Bin, <<"\\">>, <<"\\\\">>, [global]),
                <<"\"">>, <<"\\\"">>, [global]),
            <<"\n">>, <<"\\n">>, [global]),
        <<"\r">>, <<"\\r">>, [global]).

%% Extract writes array from applyWrites body
%% Returns list of {create_write, Collection, Rkey, RecordJson} | 
%%                 {update_write, Collection, Rkey, RecordJson} |
%%                 {delete_write, Collection, Rkey}
extract_writes(Body) when is_map(Body) ->
    Writes = case maps:find(<<"writes">>, Body) of
        {ok, W} when is_list(W) -> W;
        _ -> []
    end,
    lists:filtermap(fun(Write) ->
        case Write of
            Map when is_map(Map) ->
                Type = maps:get(<<"$type">>, Map, <<>>),
                Collection = maps:get(<<"collection">>, Map, <<>>),
                Rkey = maps:get(<<"rkey">>, Map, <<>>),
                case Type of
                    <<"com.atproto.repo.applyWrites#create">> ->
                        Record = maps:get(<<"value">>, Map, #{}),
                        RecordJson = encode_json(Record),
                        {true, {create_write, Collection, Rkey, RecordJson}};
                    <<"com.atproto.repo.applyWrites#update">> ->
                        Record = maps:get(<<"value">>, Map, #{}),
                        RecordJson = encode_json(Record),
                        {true, {update_write, Collection, Rkey, RecordJson}};
                    <<"com.atproto.repo.applyWrites#delete">> ->
                        {true, {delete_write, Collection, Rkey}};
                    _ -> false
                end;
            _ -> false
        end
    end, Writes);
extract_writes(_) -> [].
