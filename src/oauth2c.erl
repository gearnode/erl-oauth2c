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

-module(oauth2c).

-export([new_client/3, new_client/4,
         discover/1, discover/2,
         authorize_url/3]).

-export_type([client/0,
              response_type/0,
              scope/0, scopes/0,
              redirect_uri/0,
              authorize_code_request/0, authorize_token_request/0,
              authorize_request/0]).

-type client() :: oauth2c_client:client().

-type response_type() :: code | token.

-type scope() :: binary().
-type scopes() :: [scope()].

-type redirect_uri() :: binary().

-type authorize_code_request() :: #{state => binary(),
                                    redirect_uri => redirect_uri(),
                                    scope => scopes()}.

-type authorize_token_request() :: #{state => binary(),
                                     redirect_uri => redirect_uri(),
                                     scope => scopes()}.

-type authorize_request() ::
        authorize_code_request()
      | authorize_token_request().

-spec new_client(oauth2c_client:issuer(),
                 oauth2c_client:id(), oauth2c_client:secret()) ->
        {ok, client()} | {error, term()}.
new_client(Issuer, Id, Secret) ->
  oauth2c_client:new_client(Issuer, Id, Secret).

-spec new_client(oauth2c_client:issuer(),
                 oauth2c_client:id(), oauth2c_client:secret(),
                 oauth2c_client:options()) ->
        {ok, client()} | {error, term()}.
new_client(Issuer, Id, Secret, Options) ->
  oauth2c_client:new_client(Issuer, Id, Secret, Options).

-spec discover(client()) ->
        {ok, oauth2c_discovery:authorization_server_metadata()} |
        {error, oauth2c_discovery:discover_error_reason()}.
discover(#{issuer := Issuer}) ->
  oauth2c_discovery:discover(Issuer).

-spec discover(client(), Suffix :: binary()) ->
        {ok, oauth2c_discovery:authorization_server_metadata()} |
        {error, oauth2c_discovery:discover_error_reason()}.
discover(#{issuer := Issuer}, Suffix) ->
  oauth2c_discovery:discover(Issuer, Suffix).

-spec authorize_url(client(), response_type(), authorize_request()) ->
        {ok, binary()} | {error, term()}.
authorize_url(#{authorization_endpoint := Endpoint0, id := Id},
              ResponseType, Request) ->
  Parameters0 =
    maps:merge(Request, #{client_id => Id,
                          response_type => atom_to_binary(ResponseType)}),
  Parameters = maps:fold(fun (K0, V, Acc) ->
                             K = atom_to_binary(K0),
                             Acc#{K => V}
                         end, #{}, Parameters0),
  case uri:parse(Endpoint0) of
    {ok, Endpoint} ->
      {ok,
       uri:serialize(
         uri:add_query_parameters(Endpoint, maps:to_list(Parameters)))};
    {error, Reason} ->
      {error, {invalid_authorization_endpoint, Reason}}
  end.
