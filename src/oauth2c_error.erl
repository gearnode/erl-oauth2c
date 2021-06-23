%% Copyright (c) 2021 Bryan Frimin <bryan@frimin.fr>.
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
%% SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
%% IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

-module(oauth2c_error).

-export([error_response_definition/0,
         parse_uri/1, parse_bin/1, parse_map/1]).

-export_type([error_code/0, error_description/0, error_response/0]).

-type error_code() ::
      %% https://tools.ietf.org/html/rfc6749#section-5.2
        invalid_request
      | invalid_client
      | invalid_grant
      | unauthorized_client
      | unsupported_grant_type
      | invalid_scope
      %% https://tools.ietf.org/html/rfc7009#section-2.2.1
      | unsupported_token_type
      %% https://tools.ietf.org/html/rfc8628#section-3.5
      | slow_down
      | access_denied
      | expired_token
      | binary().

-type error_description() :: binary().

-type error_response() :: #{error := error_code(),
                            error_description => error_description(),
                            error_uri => uri:uri()}.

-spec error_response_definition() ->
        jsv:definition().
error_response_definition() ->
  {object,
   #{members =>
       #{error => string,
         error_description => string,
         error_uri => uri},
     required =>
       [error]}}.

-spec parse_uri(uri:uri()) ->
        {ok, error_response()} | {error, term()}.
parse_uri(#{query := Query}) ->
  parse_map(maps:from_list(Query)).

-spec parse_bin(binary()) ->
        {ok, error_response()} | {error, term()}.
parse_bin(Bin) when is_binary(Bin) ->
  case json:parse(Bin) of
    {ok, Data} ->
      parse_map(Data);
    {error, Reason} ->
      {error, {invalid_syntax, Reason}}
  end.

-spec parse_map(map()) -> {ok, error_response()} | {error, term()}.
parse_map(Data) ->
  Definition = error_response_definition(),
  Options = #{unknown_member_handling => keep,
              disable_verification => true,
              null_member_handling => remove,
              type_map => oauth2c_jsv:type_map()},
  case jsv:validate(Data, Definition, Options) of
    {ok, ErrorResponse} ->
      {ok, ErrorResponse};
    {error, Reason} ->
      {error, {invalid_object, Reason}}
  end.
