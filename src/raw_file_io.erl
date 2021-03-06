-module(raw_file_io).

-export([open/2, close/1, dup/1,
         initiate_pread/4, initiate_append/3, initiate_fsync/2,
         initiate_truncate/3, initiate_close/2,
         file_size/1, truncate/2, set_sync/2, suppress_writes/1]).

-export([pread/3, append/2, read/2, fsync/1]).

-on_load(init/0).


init() ->
    SoName =
        case code:priv_dir(?MODULE) of
            {error, bad_name} ->
                case filelib:is_dir(filename:join(["..", "priv"])) of
                    true ->
                        filename:join(["..", "priv", "raw_file_io_nif"]);
                    false ->
                        filename:join(["priv", "raw_file_io_nif"])
                end;
            Dir ->
                filename:join(Dir, "raw_file_io_nif")
        end,
    erlang:load_nif(SoName, 0).

open(Path, Options) ->
    do_open(iolist_to_binary(Path), parse_open_options(Options, 0)).

-define(FILE_FLAG_READ, 1).
-define(FILE_FLAG_APPEND, 2).
-define(FILE_FLAG_TRUNCATE, 16).
-define(FILE_FLAG_CREAT, 32).
-define(FILE_FLAG_EXCL, 64).
-define(FILE_FLAG_DIRECT, 256).
-define(FILE_FLAG_DATASYNC, 1024).
-define(FILE_FLAG_SYNC, 2048).

parse_open_options([], Flags) ->
    Flags;
parse_open_options([read|Rest], Flags) ->
    parse_open_options(Rest, Flags bor ?FILE_FLAG_READ);
parse_open_options([append|Rest], Flags) ->
    parse_open_options(Rest, Flags bor ?FILE_FLAG_APPEND);
parse_open_options([truncate|Rest], Flags) ->
    parse_open_options(Rest, Flags bor ?FILE_FLAG_TRUNCATE);
parse_open_options([creat|Rest], Flags) ->
    parse_open_options(Rest, Flags bor ?FILE_FLAG_CREAT);
parse_open_options([excl|Rest], Flags) ->
    parse_open_options(Rest, Flags bor ?FILE_FLAG_EXCL);
parse_open_options([direct|Rest], Flags) ->
    parse_open_options(Rest, Flags bor ?FILE_FLAG_DIRECT);
parse_open_options([datasync|Rest], Flags) ->
    parse_open_options(Rest, Flags bor ?FILE_FLAG_DATASYNC);
parse_open_options([sync|Rest], Flags) ->
    parse_open_options(Rest, Flags bor ?FILE_FLAG_SYNC);
parse_open_options(_X, _Flags) ->
    erlang:error(badarg).


do_open(_, _) ->
    erlang:nif_error(not_loaded).

dup(_) ->
    erlang:nif_error(not_loaded).

initiate_pread(_Tag, _FileRef, _Off, _Len) ->
    erlang:nif_error(not_loaded).

initiate_append(_Tag, _FileRef, _Iolist) ->
    erlang:nif_error(not_loaded).

initiate_fsync(_Tag, _FileRef) ->
    erlang:nif_error(not_loaded).

file_size(_FileRef) ->
    erlang:nif_error(not_loaded).

initiate_truncate(_Tag, _FileRef, _Pos) ->
    erlang:nif_error(not_loaded).

truncate(FileRef, Pos) ->
    Tag = erlang:make_ref(),
    case initiate_truncate(Tag, FileRef, Pos) of
        Tag ->
            receive
                {Tag, _} ->
                    ok
            end;
        Err ->
            Err
    end.

initiate_close(_Tag, _FileRef) ->
    erlang:nif_error(not_loaded).

close(FileRef) ->
    Tag = erlang:make_ref(),
    case initiate_close(Tag, FileRef) of
        Tag ->
            receive
                {Tag, RV} ->
                    RV
            end;
        Err ->
            Err
    end.

set_sync(_FileRef, _ZeroIfFalse) ->
    erlang:nif_error(not_loaded).

suppress_writes(_FileRef) ->
    erlang:nif_error(not_loaded).

read(FileRef, Len) ->
    pread(FileRef, -1, Len).

pread(_FileRef, _Off, _Len = 0) ->
    {ok, <<>>};
pread(FileRef, Off, Len) ->
    Tag = erlang:make_ref(),
    case initiate_pread(Tag, FileRef, Off, Len) of
        Tag ->
            receive
                {Tag, Value} ->
                    case Value of
                        <<>> ->
                            eof;
                        _ ->
                            {ok, Value}
                    end
            end;
        Value when is_binary(Value) ->
            case Value of
                <<>> ->
                    eof;
                _ ->
                    {ok, Value}
            end;
        Err ->
            Err
    end.

append(FileRef, IoList) ->
    Tag = erlang:make_ref(),
    case initiate_append(Tag, FileRef, IoList) of
        [] ->
            %% nil from initiate_append indicates that write is 100%
            %% background and there's no need to wait for it
            ok;
        Tag ->
            receive
                {Tag, Written, Error} ->
                    case Error of
                        Tag ->
                            ok;
                        _ ->
                            {error, Error, Written}
                    end
            end;
        Err ->
            Err
    end.

fsync(FileRef) ->
    Tag = erlang:make_ref(),
    case initiate_fsync(Tag, FileRef) of
        Tag ->
            receive
                {Tag, Error} ->
                    case Error of
                        Tag ->
                            ok;
                        _ ->
                            {error, Error}
                    end
            end;
        Err ->
            Err
    end.
