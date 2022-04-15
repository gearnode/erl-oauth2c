%% Copyright (c) 2021 Exograd SAS.
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

%% This module implement the RFC 8414 (https://tools.ietf.org/html/rfc8414).
-module(oauth2c_discovery).

-export([authorization_server_metadata_definition/0,
         discover/1, discover/2]).

-export_type([authorization_server_metadata/0,
              discover_error_reason/0]).

%% https://tools.ietf.org/html/rfc8414#section-2
-type authorization_server_metadata() ::
        #{issuer :=
            oauth2c_client:issuer(),
          authorization_endpoint =>
            uri:uri(),
          token_endpoint =>
            uri:uri(),
          jwks_uri =>
            uri:uri(),
          registration_endpoint =>
            uri:uri(),
          scopes_supported =>
            [binary()],
          response_types_supported :=
            [binary()],
          response_modes_supported =>
            [binary()],
          grant_types_supported =>
            [binary()],
          token_endpoint_auth_methods_supported =>
            [binary()],
          token_endpoint_auth_signing_alg_values_supported =>
            [binary()],
          service_documentation =>
            uri:uri(),
          ui_locales_supported =>
            [binary()],
          op_policy_uri =>
            uri:uri(),
          op_tos_uri =>
            uri:uri(),
          revocation_endpoint =>
            uri:uri(),
          revocation_endpoint_auth_methods_supported =>
            [binary()],
          revocation_endpoint_auth_signing_alg_values_supported =>
            [binary()],
          introspection_endpoint =>
            uri:uri(),
          introspection_endpoint_auth_methods_supported =>
            [binary()],
          introspection_endpoint_auth_signing_alg_values_supported =>
            [binary()],
          code_challenge_methods_supported =>
            [binary()],
          %% https://tools.ietf.org/html/rfc8628#section-4
          device_authorization_endpoint =>
            uri:uri()}.

-type discover_error_reason() ::
        {bas_resp_code, integer()}
      | {mhttp, term()}
      | {invalid_syntax, term()}
      | {invalid_metadata, term()}
      | {bad_issuer, oauth2c_client:issuer(), binary()}.

%% https://tools.ietf.org/html/rfc8414#section-2
-spec authorization_server_metadata_definition() ->
        jsv:definition().
authorization_server_metadata_definition() ->
  {object,
   #{members =>
       #{issuer => uri,
         authorization_endpoint => uri,
         token_endpoint => uri,
         jwks_uri => uri,
         registration_endpoint => uri,
         scopes_supported => {array, #{element => string}},
         response_types_supported => {array, #{element => string}},
         response_modes_supported => {array, #{element => string}},
         grant_types_supported => {array, #{element => string}},
         token_endpoint_auth_methods_supported =>
           {array, #{element => string}},
         token_endpoint_auth_signing_alg_values_supported =>
           {array, #{element => string}},
         service_documentation => uri,
         ui_locales_supported => {array, #{element => string}},
         op_policy_uri => uri,
         op_tos_uri => uri,
         revocation_endpoint => uri,
         revocation_endpoint_auth_methods_supported =>
           {array, #{element => string}},
         revocation_endpoint_auth_signing_alg_values_supported =>
           {array, #{element => string}},
         introspection_endpoint => uri,
         introspection_endpoint_auth_methods_supported =>
           {array, #{element => string}},
         introspection_endpoint_auth_signing_alg_values_supported =>
           {array, #{element => string}},
         code_challenge_methods_supported => {array, #{element => string}},
         %% https://tools.ietf.org/html/rfc8628#section-4
         device_authorization_endpoint => uri},
     required =>
       [issuer, response_types_supported]}}.

%% https://tools.ietf.org/html/rfc8414#section-3
-spec discover(oauth2c_client:issuer() | binary()) ->
        {ok, authorization_server_metadata()} |
        {error, discover_error_reason()}.
discover(Issuer) ->
  discover(Issuer, {suffix, <<".well-known/oauth-authorization-server">>}).

%% https://tools.ietf.org/html/rfc8414#section-3
-spec discover(oauth2c_client:issuer() | binary(), {suffix | endpoint, binary()}) ->
        {ok, authorization_server_metadata()} |
        {error, discover_error_reason()}.
discover(Issuer, Opt) when is_binary(Issuer) ->
  case uri:parse(Issuer) of
    {ok, URI} ->
      discover(URI, Opt);
    {error, Reason} ->
      {error, {bad_issuer, Reason}}
  end;
discover(Issuer, Opt) when is_map(Issuer) ->
  Request = #{method => get,
              target => case Opt of
                          {suffix, Suffix} ->
                            discovery_uri(Issuer, Suffix);
                          {endpoint, Endpoint} ->
                            Endpoint
                        end},
  case mhttp:send_request(Request) of
    {ok, #{status := 200, body := Data}} ->
      case parse_metadata(Data) of
        {ok, #{issuer := Issuer} = MD} ->
          {ok, MD};
        {ok, #{issuer := Value}} ->
          {error, {bad_issuer, Issuer, Value}};
        {error, Reason} ->
          {error, Reason}
      end;
    {ok, #{status := StatusCode}} ->
      {error, {bad_resp_code, StatusCode}};
    {error, Reason} ->
      {error, {mhttp, Reason}}
  end.

-spec parse_metadata(binary()) ->
        {ok, authorization_server_metadata()} |
        {error, term()}.
parse_metadata(Bin) ->
  case json:parse(Bin) of
    {ok, Data} ->
      Definition = authorization_server_metadata_definition(),
      Options = #{unknown_member_handling => keep,
                  disable_verification => true,
                  null_member_handling => remove,
                  type_map => oauth2c_jsv:type_map()},
      case jsv:validate(Data, Definition, Options) of
        {ok, Metadata} ->
          {ok, Metadata};
        {error, Reason} ->
          {error, {invalid_metadata, Reason}}
      end;
    {error, Reason} ->
      {error, {invalid_syntax, Reason}}
  end.

%% https://tools.ietf.org/html/rfc8414#section-3.1
-spec discovery_uri(uri:uri(), Suffix :: binary()) -> uri:uri().
discovery_uri(Issuer, Suffix) ->
  Clean = fun (<<$/, Rest/binary>>) -> Rest;
              (Bin) -> Bin
          end,
  Path = lists:join($/, [<<"/">>,
                         Clean(Suffix),
                         Clean(maps:get(path, Issuer, <<>>))]),
  Issuer#{path => list_to_binary(Path)}.
