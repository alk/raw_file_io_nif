-module(raw_file_io_tests).
-include_lib("eunit/include/eunit.hrl").

init_test() ->
    ?assertEqual(true, lists:member(raw_file_io, erlang:loaded())).

tmpname(Basename) ->
    {ok, Cwd} = file:get_cwd(),
    Basedir = case filename:basename(Cwd) of
                  ".eunit" ->
                      filename:join(Cwd, "..");
                  _ ->
                      error(dont_know)
              end,
    filename:join([Basedir, "tmp", Basename]).

setup_file(Basename) ->
    Name = tmpname(Basename),
    file:delete(Name),
    {ok, _} = file:read_file_info(filename:dirname(Name)),
    {error, enoent} = file:read_file_info(Name),
    {ok, F} = file:open(Name, [binary, read, write]),
    ok = file:write(F, <<"Some initial stuff", 10:8>>),
    ok = file:close(F),
    list_to_binary(Name).

write_and_read_test() ->
    Name = setup_file("write_and_read_file"),

    {ok, Ref1} = raw_file_io:open(Name, [read, append]),
    {ok, Ref2} = raw_file_io:dup(Ref1),
    ?assertNotMatch({error, _}, Ref2),

    receive
        _ ->
            error(unexpected)
    after 0 ->
            ok
    end,

    Tag = erlang:make_ref(),

    RV0 = raw_file_io:initiate_pread(Tag, Ref1, 4, 1024),
    ?assertEqual(Tag, RV0),
    receive
        V ->
            ?assertMatch({Tag, _}, V)
    end,

    {ok, Read1} = raw_file_io:pread(Ref2, 5, 1024),
    ?assertEqual(<<"initial stuff", 10:8>>, Read1),

    ok = raw_file_io:append(Ref1, <<"and some further stuff\n">>),

    {andRead, {ok, Read2}} = {andRead, raw_file_io:pread(Ref2, erlang:size(Read1) + 5, 3)},
    ?assertEqual(<<"and">>, Read2),

    ok = raw_file_io:close(Ref2),

    {ok, Read3} = raw_file_io:pread(Ref1, erlang:size(Read1) + 5, 1024),
    ?assertEqual(<<"and some further stuff\n">>, Read3),

    {ok, Ref3} = raw_file_io:open(Name, [append]),

    ok = raw_file_io:append(Ref3, <<"more\n">>),
    ok = raw_file_io:append(Ref3, <<"even more\n">>),

    ok = raw_file_io:close(Ref3),

    ?assertEqual(<<"Some initial stuff\nand some further stuff\nmore\neven more\n">>,
                 element(2, raw_file_io:pread(Ref1, 0, 1024))),

    ok = raw_file_io:close(Ref1),

    ok.

access_on_closed_ref_test() ->
    Name = setup_file("access_on_closed_ref_file"),

    {ok, Ref1} = raw_file_io:open(Name, [read, append]),

    ?assertEqual(<<"Some initial stuff\n">>, element(2, raw_file_io:pread(Ref1, 0, 1024))),

    {ok, Ref2} = raw_file_io:dup(Ref1),

    ok = raw_file_io:close(Ref1),
    {error, badarg} = raw_file_io:close(Ref1),

    ?assertMatch({error, _}, raw_file_io:pread(Ref1, 0, 1024)),

    ok = raw_file_io:close(Ref2),

    ok.

errno_test() ->
    ?assertEqual({error, enoent}, raw_file_io:open(<<"/this/cannot/ever/exist">>, [read, append])).

large_files_test() ->
    Name = setup_file("large_file"),
    {ok, F} = file:open(Name, [read, write, binary]),
    ok = file:pwrite(F, 0, <<"zero">>),
    ok = file:pwrite(F, 16#080000000, <<"one">>),
    ok = file:pwrite(F, 16#200000000, <<"two">>),
    file:close(F),
    {ok, Ref} = raw_file_io:open(Name, [read]),
    ?assertEqual(<<"zero">>, element(2, raw_file_io:pread(Ref, 0, 4))),
    ?assertEqual(<<"one", 0:8>>, element(2, raw_file_io:pread(Ref, 2*1024*1024*1024, 4))),
    ?assertEqual(<<"two">>, element(2, raw_file_io:pread(Ref, 8*1024*1024*1024, 4))),
    ok = raw_file_io:close(Ref),
    ok.

fsync_test() ->
    Name = setup_file("fsync_file"),
    {ok, Ref} = raw_file_io:open(Name, [read, append]),
    ok = raw_file_io:fsync(Ref),
    ok = raw_file_io:close(Ref).

initiate_msg_pread(Tag, FileRef, Off, Len) ->
    case raw_file_io:initiate_pread(Tag, FileRef, Off, Len) of
        Tag ->
            Tag;
        Bin when is_binary(Bin) ->
            self() ! {Tag, Bin},
            Tag;
        Err ->
            Err
    end.

leak_test_loop(InFlightSet, Counter, FileRef) ->
    receive
        {Tag, Result} ->
            {tag, true, Tag} = {tag, sets:is_element(Tag, InFlightSet), Tag},
            {is_binary, true} = {is_binary, is_binary(Result)},
            InFlightSet0 = sets:del_element(Tag, InFlightSet),
            case Counter of
                0 ->
                    case sets:size(InFlightSet0) =:= 0 of
                        true -> done;
                        _ ->
                            leak_test_loop(InFlightSet0, Counter, FileRef)
                    end;
                _ ->
                    RV = initiate_msg_pread(
                           Counter, FileRef,
                           1024*1024*1024*1024 + Counter, 1024),
                    {started_read, Counter} = {started_read, RV},
                    InFlightSet1 = sets:add_element(Counter, InFlightSet0),
                    leak_test_loop(InFlightSet1, Counter - 1, FileRef)
            end
    end.

leak_test_run(ReqsTotal, Concurrency, FileRef) ->
    L = [N = initiate_msg_pread(N, FileRef, 0, 0)
         || N <- lists:seq(ReqsTotal + 1, ReqsTotal + Concurrency)],
    leak_test_loop(sets:from_list(L), ReqsTotal, FileRef).

leak_test_() ->
    {timeout, 60,
     fun () ->
             Name = setup_file("leak_file"),
             {ok, Ref} = raw_file_io:open(Name, [read]),
             Runs = case os:getenv("ONLY_BRIEF_TESTS") of
                        false ->
                            2000000;
                        _ ->
                            20000
                    end,
             leak_test_run(Runs, 64, Ref),
             ok = raw_file_io:close(Ref)
     end}.

exotic_flags_support_test() ->
    Name = setup_file("exotic_flags_file"),
    {ok, Ref} = raw_file_io:open(Name, [read, append, sync]),
    ok = raw_file_io:close(Ref),
    BadValue = (catch raw_file_io:open(Name, [read, append, direct,
                                              datasync, sync,
                                              something])),
    ?assertMatch({'EXIT', {badarg, _}}, BadValue),

    ok = file:delete(Name),

    ?assertEqual({error, enoent},
                 raw_file_io:open(Name, [read, append, sync])),

    {ok, Ref2} = raw_file_io:open(Name, [read, append, creat]),

    ok = raw_file_io:close(Ref2),
    ok.

test_reading_past_eof_test() ->
    Name = setup_file("reading_past_eof_file"),
    {ok, Ref} = raw_file_io:open(Name, [read, append]),
    ok = raw_file_io:truncate(Ref, 0),
    ok = raw_file_io:append(Ref, <<"aaaa">>),
    ?assertEqual({ok, <<"aa">>}, raw_file_io:pread(Ref, 2, 4)),
    ?assertEqual({ok, <<>>}, raw_file_io:pread(Ref, 3, 0)),
    ?assertEqual({ok, <<>>}, raw_file_io:pread(Ref, 4, 0)),
    ?assertEqual({ok, <<>>}, raw_file_io:pread(Ref, 5, 0)),
    ?assertEqual(eof, raw_file_io:pread(Ref, 4, 1)),
    ?assertEqual(eof, raw_file_io:pread(Ref, 4, 23)),
    ok.

settings_sync_works_test() ->
    Name = setup_file("settings_sync_works_file"),
    {ok, Ref} = raw_file_io:open(Name, [read, append]),
    ?assertEqual({ok, <<"S">>}, raw_file_io:pread(Ref, 0, 1)),
    ok = raw_file_io:set_sync(Ref, 1),
    ?assertEqual({ok, <<"S">>}, raw_file_io:pread(Ref, 0, 1)),
    ok.

dotimes(0, _F) ->
    ok;
dotimes(N, F) ->
    F(N),
    dotimes(N-1, F).

raw_efile_bench_test() ->
    Name = setup_file("raw_efile_bench_file"),
    {ok, F} = file:open(Name, [read, raw, write, binary]),
    ok = file:write(F, <<"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">>),
    erlang:garbage_collect(),
    dotimes(100000, fun (_) ->
                           {ok, _} = file:pread(F, 0, 10)
                   end),
    file:close(F).

efile_bench_test() ->
    Name = setup_file("efile_bench_file"),
    {ok, F} = file:open(Name, [read, write, binary]),
    ok = file:write(F, <<"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">>),
    erlang:garbage_collect(),
    dotimes(100000, fun (_) ->
                           {ok, _} = file:pread(F, 0, 10)
                   end),
    file:close(F).

async_bench_test() ->
    Name = setup_file("async_bench_file"),
    {ok, F} = raw_file_io:open(Name, [read, append, truncate]),
    ok = raw_file_io:append(F, <<"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">>),
    erlang:garbage_collect(),
    dotimes(1000000, fun (_) ->
                             {ok, _} = raw_file_io:pread(F, 0, 10)
                     end),
    raw_file_io:close(F).

async_write_bench_test_() ->
    {timeout, 120, fun async_write_bench_test_fun/0}.

async_write_bench_test_fun() ->
    Name = setup_file("async_write_bench_file"),
    {ok, F} = raw_file_io:open(Name, [read, append, truncate]),
    ok = raw_file_io:append(F, <<"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">>),
    erlang:garbage_collect(),
    Bin = <<"asdasdasdasdasdasdadsasdasdasdaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">>,
    dotimes(100000,
            fun (_) ->
                    raw_file_io:truncate(F, 1024*1024),
                    ok = raw_file_io:append(F, Bin)
            end),
    raw_file_io:close(F).

sync_bench_test() ->
    Name = setup_file("async_bench_file"),
    {ok, F} = raw_file_io:open(Name, [read, append, truncate]),
    ok = raw_file_io:append(F, <<"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">>),
    raw_file_io:set_sync(F, 1),
    erlang:garbage_collect(),
    dotimes(100000, fun (_) ->
                           {ok, _} = raw_file_io:pread(F, 0, 10)
                   end),
    raw_file_io:close(F).

write_suppression_test() ->
    Name = setup_file("write_suppression_test"),
    {ok, F} = raw_file_io:open(Name, [read, append, truncate]),
    ok = raw_file_io:append(F, <<"asd">>),
    ok = raw_file_io:suppress_writes(F),
    {error, write_closed} = raw_file_io:append(F, <<"asd">>),
    ok = raw_file_io:close(F),
    ok.
