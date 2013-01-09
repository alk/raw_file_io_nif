%% Copyright 2011,  Filipe David Manana  <fdmanana@apache.org>
%% Web:  http://github.com/fdmanana/snappy-erlang-nif
%%
%% Licensed under the Apache License, Version 2.0 (the "License"); you may not
%% use this file except in compliance with the License. You may obtain a copy of
%% the License at
%%
%%  http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
%% WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
%% License for the specific language governing permissions and limitations under
%% the License.

-module(raw_file_io).

-export([open/2, close/1, dup/1,
         initiate_pread/4, initiate_append/3, initiate_fsync/2,
         file_size/1, truncate/2]).

-export([pread/3, append/2, fsync/1]).

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

close(_) ->
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

truncate(_FileRef, _Pos) ->
    erlang:nif_error(not_loaded).

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
        Err ->
            Err
    end.

append(FileRef, IoList) ->
    Tag = erlang:make_ref(),
    case initiate_append(Tag, FileRef, IoList) of
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
