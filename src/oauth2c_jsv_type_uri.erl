%% Copyright (c) 2022 Bryan Frimin <bryan@frimin.fr>.
%% Copyright (c) 2021 Exograd SAS.
%% Copyright (c) 2020 Bryan Frimin <bryan@frimin.fr>.
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

-module(oauth2c_jsv_type_uri).

-behaviour(jsv_type).

-export([validate_type/2, canonicalize/3, generate/2]).

validate_type(<<"">>, _) ->
  error;
validate_type(Value, _) when is_binary(Value) ->
  case uri:parse(Value) of
    {ok, URI} ->
      {ok, Value, URI};
    {error, _} ->
      error
  end;
validate_type(_, _) ->
  error.

canonicalize(_, URI, _) ->
  URI.

generate(Term, _) when is_map(Term) ->
  {ok, uri:serialize(Term)};
generate(_, _) ->
  error.
