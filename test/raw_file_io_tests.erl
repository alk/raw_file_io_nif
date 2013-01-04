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
