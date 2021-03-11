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
         authorize_url/3,
         token_response_definition/0,
         request_token/3]).

-export_type([error/0,
              client/0,
              response_type/0,
              scope/0, scopes/0,
              redirect_uri/0,
              authorize_code_request/0, authorize_implicit_request/0,
              authorize_request/0,
              grant_type/0,
              token_code_request/0, token_owner_creds_request/0,
              token_client_creds_request/0, token_refresh_request/0,
              token_request/0,
              token_response/0]).

-type error() :: oauth2c_error:error_response().

-type client() :: oauth2c_client:client().

-type response_type() :: binary().

-type scope() :: binary().
-type scopes() :: [scope()].

-type redirect_uri() :: binary().

-type authorize_code_request() ::
        #{state => binary(),
          redirect_uri => redirect_uri(),
          scope => scopes(),
          atom() => binary()}.

-type authorize_implicit_request() ::
        #{state => binary(),
          redirect_uri => redirect_uri(),
          scope => scopes(),
          atom() => binary()}.

-type authorize_request() ::
        authorize_code_request()
      | authorize_implicit_request().

-type grant_type() :: binary().

-type token_code_request() ::
        #{code := binary(),
          redirect_uri => binary(),
          state => binary()}.

-type token_owner_creds_request() ::
        #{username := binary(),
          password := binary(),
          scope => scopes(),
          atom() => binary()}.

-type token_client_creds_request() ::
        #{scope => scopes(),
          atom() => binary()}.

-type token_refresh_request() ::
        #{refresh_token := binary(),
          scope => scopes(),
          atom() => binary()}.

-type token_request() ::
        token_code_request()
      | token_owner_creds_request()
      | token_client_creds_request()
      | token_refresh_request().

-type token_response() ::
        #{access_token := binary(),
          token_type := binary(),
          expires_in => integer(),
          refresh_token => binary(),
          scope => binary(),
          binary() => json:value()}.

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
  Parameters =
    maps:fold(fun (K0, V, Acc) -> K = atom_to_binary(K0), Acc#{K => V} end,
              #{},
              maps:merge(Request,
                         #{client_id => Id, response_type => ResponseType})),
  case uri:parse(Endpoint0) of
    {ok, Endpoint} ->
      {ok,
       uri:serialize(
         uri:add_query_parameters(Endpoint, maps:to_list(Parameters)))};
    {error, Reason} ->
      {error, {invalid_authorization_endpoint, Reason}}
  end.

-spec request_token(client(), grant_type(), token_request()) ->
        {ok, token_response()} | {error, {oauth2, error()} | term()}.
request_token(#{id := Id, secret := Secret, token_endpoint := Endpoint},
              GrantType, Parameters0) ->
  Token = b64:encode(<<Id/binary, $:, Secret/binary>>),
  Parameters =
    maps:fold(fun (K0, V, Acc) -> K = atom_to_binary(K0), Acc#{K => V} end,
              #{},
              maps:merge(Parameters0,
                         #{grant_type => GrantType, client_id => Id})),
  Request = #{method => post, target => Endpoint,
              header =>
                [{<<"Authorization">>, <<"Basic ", Token/binary>>},
                 {<<"Content-Type">>, <<"application/x-www-form-urlencoded">>},
                 {<<"Accept">>, <<"application/json">>}],
              body => uri:encode_query(maps:to_list(Parameters))},
  case mhttp:send_request(Request) of
    {ok, #{body := Bin}} ->
      case json:parse(Bin) of
        {ok, #{<<"error">> := _}} ->
          case oauth2c_error:parse(Bin) of
            {ok, ErrorResponse} ->
              {error, {oauth2, ErrorResponse}};
            {error, Reason} ->
              {error, {invalid_response, Reason}}
          end;
        {ok, TokenData} ->
          Definition = token_response_definition(),
          Options = #{unknown_member_handling => keep,
                      disable_verification => true,
                      null_member_handling => remove},
          case jsv:validate(TokenData, Definition, Options) of
            {ok, TokenResponse} ->
              {ok, TokenResponse};
            {error, Reason} ->
              {error, {invalid_response, Reason}}
          end;
        {error, Reason} ->
          {error, {invalid_response, Reason}}
      end;
    {error, Reason} ->
      {error, {invalid_response, Reason}}
  end;
request_token(_, GrantType, _) ->
  {error, {unsupported_grant_type, GrantType}}.

-spec token_response_definition() ->
        jsv:definition().
token_response_definition() ->
  {object,
     #{members =>
         #{access_token => string,
           token_type => string,
           expires_in => string,
           refresh_token => string,
           scope => string},
       required =>
         [access_token, token_type]}}.
