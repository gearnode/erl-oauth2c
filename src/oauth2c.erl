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
         token/3,
         introspect_response_definition/0,
         introspect/3,
         revoke/3,
         device_authorize_response_definition/0,
         device/2]).

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
              token_device_request/0, token_request/0, token_response/0,
              introspect_request/0, introspect_response/0,
              revoke_token_request/0,
              device_authorize_request/0, device_authorize_response/0]).

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

-type token_device_request() :: #{}.

-type token_request() ::
        token_code_request()
      | token_owner_creds_request()
      | token_client_creds_request()
      | token_refresh_request()
      | token_device_request().

-type token_response() ::
        #{access_token := binary(),
          token_type := binary(),
          expires_in => integer(),
          refresh_token => binary(),
          scope => binary(),
          binary() => json:value()}.

-type introspect_request() ::
        #{token_type_hint => binary(),
          atom() => binary()}.

-type introspect_response() ::
        #{active := boolean(),
          scope => scopes(),
          client_id => oauth2c_client:id(),
          username => binary(),
          token_type => binary(),
          exp => integer(),
          iat => integer(),
          nbf => integer(),
          sub => binary(),
          aud => binary(),
          iss => binary(),
          jti => binary(),
          binary() => json:value()}.

%% https://tools.ietf.org/html/rfc7009#section-2.1
-type revoke_token_request() ::
        #{token_type_hint => binary(),
          atom() => binary()}.

%% https://tools.ietf.org/html/rfc8628
-type device_authorize_request() ::
        #{scope => scopes()}.

%% https://tools.ietf.org/html/rfc8628
-type device_authorize_response() ::
        #{device_code := binary(),
          user_code := binary(),
          verification_uri := binary(),
          verification_uri_complete => binary(),
          expires_in := integer(),
          interval => integer()}.

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
        {ok, uri:uri()} | {error, term()}.
authorize_url(#{authorization_endpoint := Endpoint0, id := Id},
              ResponseType, Request) ->
  Parameters =
    maps:fold(fun (K0, V, Acc) -> K = atom_to_binary(K0), Acc#{K => V} end,
              #{},
              maps:merge(Request,
                         #{client_id => Id, response_type => ResponseType})),
  case uri:parse(Endpoint0) of
    {ok, Endpoint} ->
      {ok, uri:add_query_parameters(Endpoint, maps:to_list(Parameters))};
    {error, Reason} ->
      {error, {invalid_authorization_endpoint, Reason}}
  end.

-spec token(client(), grant_type(), token_request()) ->
        {ok, token_response()} | {error, {oauth2, error()} | term()}.
token(#{id := Id, secret := Secret, token_endpoint := Endpoint},
      GrantType, Parameters0) ->
  Token = b64:encode(<<Id/binary, $:, Secret/binary>>),
  Parameters =
    maps:fold(fun (K0, V, Acc) -> K = atom_to_binary(K0), Acc#{K => V} end,
              #{},
              maps:merge(Parameters0,
                         #{grant_type => GrantType})),
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
  end.

-spec token_response_definition() ->
        jsv:definition().
token_response_definition() ->
  {object,
   #{members =>
       #{access_token => string,
         token_type => string,
         expires_in => integer,
         refresh_token => string,
         scope => string},
     required =>
       [access_token, token_type]}}.

-spec introspect_response_definition() ->
        jsv:definition().
introspect_response_definition() ->
  {object,
   #{members =>
       #{active => boolean,
         scope => string,
         client_id => string,
         username => string,
         token_type => string,
         exp => integer,
         iat => integer,
         nbf => integer,
         sub => string,
         aud => string,
         iss => string,
         jti => string},
     required =>
       [active]}}.

%% https://tools.ietf.org/html/rfc7662
-spec introspect(client(), binary(), introspect_request()) ->
        {ok, introspect_response()} | {error, term()}.
introspect(#{id := Id, secret := Secret, introspection_endpoint := Endpoint},
           IntrospectToken, Parameters0) ->
  Token = b64:encode(<<Id/binary, $:, Secret/binary>>),
  Parameters =
    maps:fold(fun (K0, V, Acc) -> K = atom_to_binary(K0), Acc#{K => V} end,
              #{token => IntrospectToken}, Parameters0),
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
        {ok, IntrospectData} ->
          Definition = introspect_response_definition(),
          Options = #{unknown_member_handling => keep,
                      disable_verification => true,
                      null_member_handling => remove},
          case jsv:validate(IntrospectData, Definition, Options) of
            {ok, IntrospectResponse} ->
              {ok, IntrospectResponse};
            {error, Reason} ->
              {error, {invalid_response, Reason}}
          end;
        {error, Reason} ->
          {error, {invalid_response, Reason}}
      end;
    {error, Reason} ->
      {error, {invalid_response, Reason}}
  end.

%% https://tools.ietf.org/html/rfc7009
-spec revoke(client(), binary(), revoke_token_request()) ->
        ok | {error, term()}.
revoke(#{id := Id, secret := Secret, revocation_endpoint := Endpoint},
       RevokeToken, Parameters0) ->
  Token = b64:encode(<<Id/binary, $:, Secret/binary>>),
  Parameters =
    maps:fold(fun (K0, V, Acc) -> K = atom_to_binary(K0), Acc#{K => V} end,
              #{token => RevokeToken}, Parameters0),

  Request = #{method => post, target => Endpoint,
              header =>
                [{<<"Authorization">>, <<"Basic ", Token/binary>>},
                 {<<"Content-Type">>, <<"application/x-www-form-urlencoded">>},
                 {<<"Accept">>, <<"application/json">>}],
              body => uri:encode_query(maps:to_list(Parameters))},
  case mhttp:send_request(Request) of
    {ok, #{status := 200}} ->
      ok;
    {ok, #{body := Bin}} ->
      case oauth2c_error:parse(Bin) of
        {ok, ErrorResponse} ->
          {error, {oauth2, ErrorResponse}};
        {error, Reason} ->
          {error, {invalid_response, Reason}}
      end;
    {error, Reason} ->
      {error, {invalid_response, Reason}}
  end.

device_authorize_response_definition() ->
  {object,
   #{members =>
       #{device_code => string,
         user_code => string,
         verification_uri => uri,
         verification_uri_complete => uri,
         expires_in => integer,
         interval => integer},
     required =>
       [device_code, user_code, verification_uri, expires_in]}}.

-spec device(client(), device_authorize_request()) ->
        {ok, device_authorize_response()} | {error, term()}.
device(#{id := Id, secret := Secret, device_authorization_endpoint := Endpoint},
       Parameters0) ->
  Token = b64:encode(<<Id/binary, $:, Secret/binary>>),
  Parameters =
    maps:fold(fun (K0, V, Acc) -> K = atom_to_binary(K0), Acc#{K => V} end,
              #{},
              maps:merge(Parameters0, #{client_id => Id})),
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
        {ok, DeviceData} ->
          Definition = device_authorize_response_definition(),
          Options = #{unknown_member_handling => keep,
                      disable_verification => true,
                      null_member_handling => remove},
          case jsv:validate(DeviceData, Definition, Options) of
            {ok, DeviceResponse} ->
              {ok, DeviceResponse};
            {error, Reason} ->
              {error, {invalid_response, Reason}}
          end;
        {error, Reason} ->
          {error, {invalid_response, Reason}}
      end;
    {error, Reason} ->
      {error, {invalid_response, Reason}}
  end.
