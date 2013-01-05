-module(raw_file_io_tests).
-include_lib("eunit/include/eunit.hrl").

init_test() ->
    ?assertEqual(true, lists:member(raw_file_io, erlang:loaded())).

do_nothing_test() ->
    ?assertEqual(nif, raw_file_io:do_nothing(1)).

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

    Ref1 = raw_file_io:open(Name, [read, append]),
    ?assertNotMatch({error, _}, Ref1),
    Ref2 = raw_file_io:dup(Ref1),
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

    Read1 = raw_file_io:pread(Ref2, 5, 1024),
    ?assertEqual(<<"initial stuff", 10:8>>, Read1),

    ok = raw_file_io:append(Ref1, <<"and some further stuff\n">>),

    Read2 = raw_file_io:pread(Ref2, erlang:size(Read1) + 5, 3),
    ?assertEqual(<<"and">>, Read2),

    ok = raw_file_io:close(Ref2),

    Read3 = raw_file_io:pread(Ref1, erlang:size(Read1) + 5, 1024),
    ?assertEqual(<<"and some further stuff\n">>, Read3),

    Ref3 = raw_file_io:open(Name, [append]),
    ?assertNotMatch({error, _}, Ref3),

    ok = raw_file_io:append(Ref3, <<"more\n">>),
    ok = raw_file_io:append(Ref3, <<"even more\n">>),

    ok = raw_file_io:close(Ref3),

    ?assertEqual(<<"Some initial stuff\nand some further stuff\nmore\neven more\n">>,
                 raw_file_io:pread(Ref1, 0, 1024)),

    ok = raw_file_io:close(Ref1),

    ok.

access_on_closed_ref_test() ->
    Name = setup_file("access_on_closed_ref_file"),

    Ref1 = raw_file_io:open(Name, [read, append]),
    ?assertNotMatch({error, _}, Ref1),

    ?assertEqual(<<"Some initial stuff\n">>, raw_file_io:pread(Ref1, 0, 1024)),

    Ref2 = raw_file_io:dup(Ref1),
    ?assertNotMatch({error, _}, Ref2),

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
    Ref = raw_file_io:open(Name, [read]),
    ?assertEqual(<<"zero">>, raw_file_io:pread(Ref, 0, 4)),
    ?assertEqual(<<"one", 0:8>>, raw_file_io:pread(Ref, 2*1024*1024*1024, 4)),
    ?assertEqual(<<"two">>, raw_file_io:pread(Ref, 8*1024*1024*1024, 4)),
    raw_file_io:close(Ref),
    ok.

fsync_test() ->
    Name = setup_file("fsync_file"),
    Ref = raw_file_io:open(Name, [read, append]),
    ok = raw_file_io:fsync(Ref),
    ok = raw_file_io:close(Ref).

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
                    RV = raw_file_io:initiate_pread(
                           Counter, FileRef,
                           1024*1024*1024*1024 + Counter, 1024),
                    {started_read, Counter} = {started_read, RV},
                    InFlightSet1 = sets:add_element(Counter, InFlightSet0),
                    leak_test_loop(InFlightSet1, Counter - 1, FileRef)
            end
    end.

leak_test_run(ReqsTotal, Concurrency, FileRef) ->
    L = [N = raw_file_io:initiate_pread(N, FileRef, 0, 0)
         || N <- lists:seq(ReqsTotal + 1, ReqsTotal + Concurrency)],
    leak_test_loop(sets:from_list(L), ReqsTotal, FileRef).

leak_test_() ->
    {timeout, 60,
     fun () ->
             Name = setup_file("leak_file"),
             Ref = raw_file_io:open(Name, [read]),
             leak_test_run(2000000, 64, Ref),
             ok = raw_file_io:close(Ref)
     end}.
