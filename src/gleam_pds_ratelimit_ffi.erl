%% In-memory fixed-window rate limiting backed by a single public ETS table.
%%
%% Rows are {{Bucket, Key, WindowSeconds}, WindowIndex, Count}. WindowIndex is
%% the current unix second divided by WindowSeconds, so a row rolls over on its
%% own without a timer. A cheap probabilistic sweep drops rows whose window is
%% two or more windows old, which keeps the table bounded without a supervisor.
%%
%% This is per-node state: it resets on restart and is not shared across
%% machines. That is deliberate — this is spam control, not billing.
-module(gleam_pds_ratelimit_ffi).

-export([init/0, check/4, reset_all/0]).

-define(TABLE, gleam_pds_rate_limits).
-define(SWEEP_KEY, '$sweep').
-define(SWEEP_EVERY, 1000).

%% Create the ETS table if it does not exist yet. Called at startup from the
%% main process (which owns the table for the life of the node) and again,
%% defensively, from every check.
init() ->
    case ets:info(?TABLE, size) of
        undefined ->
            try
                ets:new(?TABLE, [
                    named_table,
                    public,
                    set,
                    {write_concurrency, true},
                    {read_concurrency, true}
                ]),
                nil
            catch
                %% Lost a race with another process creating it.
                _:_ -> nil
            end;
        _ ->
            nil
    end.

%% check(Bucket, Key, Limit, WindowSeconds) -> allowed | {limited, RetryAfter}
%%
%% Bucket names the rule ("createAccount:hour"), Key names the subject (an IP
%% or a token fingerprint). RetryAfter is whole seconds until the window rolls.
check(Bucket, Key, Limit, WindowSeconds) when
    is_integer(Limit), is_integer(WindowSeconds), WindowSeconds > 0
->
    init(),
    Now = erlang:system_time(second),
    Window = Now div WindowSeconds,
    Id = {Bucket, Key, WindowSeconds},
    Count = bump(Id, Window),
    maybe_sweep(Now),
    case Count =< Limit of
        true ->
            allowed;
        false ->
            RetryAfter = ((Window + 1) * WindowSeconds) - Now,
            {limited, erlang:max(RetryAfter, 1)}
    end;
check(_Bucket, _Key, _Limit, _WindowSeconds) ->
    allowed.

%% Increment the counter for this window, resetting it if the stored row
%% belongs to an earlier window.
bump(Id, Window) ->
    try
        Count = ets:update_counter(?TABLE, Id, {3, 1}, {Id, Window, 0}),
        case ets:lookup(?TABLE, Id) of
            [{_, Window, _}] ->
                Count;
            [{_, _StaleWindow, _}] ->
                ets:insert(?TABLE, {Id, Window, 1}),
                1;
            [] ->
                ets:insert(?TABLE, {Id, Window, 1}),
                1
        end
    catch
        %% Table vanished (should not happen); fail open rather than 500.
        _:_ -> 1
    end.

maybe_sweep(Now) ->
    try ets:update_counter(?TABLE, ?SWEEP_KEY, {3, 1}, {?SWEEP_KEY, 0, 0}) of
        N when N rem ?SWEEP_EVERY =:= 0 -> sweep(Now);
        _ -> ok
    catch
        _:_ -> ok
    end.

%% Delete rows whose window ended at least one full window ago. The sweep
%% counter row has an atom key and so never matches this pattern.
sweep(Now) ->
    MatchSpec = [
        {
            {{'_', '_', '$1'}, '$2', '_'},
            [{'<', {'*', {'+', '$2', 2}, '$1'}, Now}],
            [true]
        }
    ],
    catch ets:select_delete(?TABLE, MatchSpec),
    ok.

%% Drop all counters. Intended for tests and manual ops.
reset_all() ->
    init(),
    catch ets:delete_all_objects(?TABLE),
    nil.
