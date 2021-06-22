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

-module(oauth2c_client).

-export([new_client/3, new_client/4]).

-export_type([issuer/0, id/0, secret/0,
              client/0,
              options/0]).

-type issuer() :: uri:uri().
-type id() :: binary().
-type secret() :: binary().

-type client() :: #{issuer := issuer(),
                    id := id(),
                    secret := secret(),
                    discovery =>
                      oauth2c_discovery:authorization_server_metadata(),
                    authorization_endpoint := uri:uri(),
                    token_endpoint := uri:uri(),
                    introspection_endpoint := uri:uri(),
                    revocation_endpoint := uri:uri(),
                    device_authorization_endpoint := uri:uri()}.

-type options() :: #{discover => boolean(),
                     discover_suffix => binary(),
                     authorization_endpoint => uri:uri() | binary(),
                     token_endpoint => uri:uri() | binary(),
                     introspection_endpoint => uri:uri() | binary(),
                     revocation_endpoint => uri:uri() | binary(),
                     device_authorization_endpoint => uri:uri() | binary()}.

-spec new_client(issuer(), id(), secret()) ->
        {ok, client()} | {error, term()}.
new_client(Issuer, Id, Secret) ->
  new_client(Issuer, Id, Secret, #{}).

-spec new_client(issuer(), id(), secret(), options()) ->
        {ok, client()} | {error, term()}.
new_client(Issuer, Id, Secret, Options) when is_binary(Issuer) ->
  case uri:parse(Issuer) of
    {ok, URI} ->
      new_client(URI, Id, Secret, Options);
    {error, Reason} ->
      {error, {invalid_issuer, Reason}}
  end;
new_client(Issuer, Id, Secret, Options) ->
  case maybe_discover(Issuer, Options) of
    {ok, Discovery} ->
      {ok,
       #{issuer => Issuer, id => Id, secret => Secret,
         authorization_endpoint =>
           build_authorization_endpoint(Issuer, Discovery, Options),
         token_endpoint =>
           build_token_endpoint(Issuer, Discovery, Options),
         introspection_endpoint =>
           build_introspect_endpoint(Issuer, Discovery, Options),
         revocation_endpoint =>
           build_revocation_endpoint(Issuer, Discovery, Options),
         device_authorization_endpoint =>
           build_device_authorization_endpoint(Issuer, Discovery, Options),
         discovery => Discovery}};
    {error, Reason} ->
      {error, {discovery_failed, Reason}}
  end.

-spec maybe_discover(issuer(), options()) ->
        {ok, map()} |
        {error, oauth2c_discovery:discover_error_reason()}.
maybe_discover(Issuer, #{discover := true, discover_suffix := Suffix}) ->
  oauth2c_discovery:discover(Issuer, Suffix);
maybe_discover(Issuer, #{discover := true}) ->
  oauth2c_discovery:discover(Issuer);
maybe_discover(_, _) ->
  {ok, #{}}.


-spec build_authorization_endpoint(uri:uri(), map(), map()) ->
        uri:uri().
build_authorization_endpoint(Issuer, Discovery, Options) ->
  case maps:find(authorization_endpoint, Discovery) of
    {ok, Value} ->
      Value;
    error ->
      case maps:find(authorization_endpoint, Options) of
        {ok, Value} ->
          case uri:parse(Value) of
            {ok, URI} ->
              URI;
            {error, Reason} ->
              error({invalid_option, authorization_endpoint, Reason})
          end;
        error ->
          Issuer#{path => <<"/authorize">>}
      end
  end.

-spec build_token_endpoint(uri:uri(), map(), map()) ->
        uri:uri().
build_token_endpoint(Issuer, Discovery, Options) ->
  case maps:find(token_endpoint, Discovery) of
    {ok, Value} ->
      Value;
    error ->
      case maps:find(token_endpoint, Options) of
        {ok, Value} ->
          case uri:parse(Value) of
            {ok, URI} ->
              URI;
            {error, Reason} ->
              error({invalid_option, token_endpoint, Reason})
          end;
        error ->
          Issuer#{path => <<"/token">>}
      end
  end.

-spec build_introspect_endpoint(uri:uri(), map(), map()) ->
        uri:uri().
build_introspect_endpoint(Issuer, Discovery, Options) ->
  case maps:find(introspection_endpoint, Discovery) of
    {ok, Value} ->
      Value;
    error ->
      case maps:find(introspection_endpoint, Options) of
        {ok, Value} ->
          case uri:parse(Value) of
            {ok, URI} ->
              URI;
            {error, Reason} ->
              error({invalid_option, introspection_endpoint, Reason})
          end;
        error ->
          Issuer#{path => <<"/introspect">>}
      end
  end.

-spec build_revocation_endpoint(uri:uri(), map(), map()) ->
        uri:uri().
build_revocation_endpoint(Issuer, Discovery, Options) ->
  case maps:find(revocation_endpoint, Discovery) of
    {ok, Value} ->
      Value;
    error ->
      case maps:find(revocation_endpoint, Options) of
        {ok, Value} ->
          case uri:parse(Value) of
            {ok, URI} ->
              URI;
            {error, Reason} ->
              error({invalid_option, revocation_endpoint, Reason})
          end;
        error ->
          Issuer#{path => <<"/revoke">>}
      end
  end.

-spec build_device_authorization_endpoint(uri:uri(), map(), map()) ->
        uri:uri().
build_device_authorization_endpoint(Issuer, Discovery, Options) ->
  case maps:find(device_authorization_endpoint, Discovery) of
    {ok, Value} ->
      Value;
    error ->
      case maps:find(device_authorization_endpoint, Options) of
        {ok, Value} ->
          case uri:parse(Value) of
            {ok, URI} ->
              URI;
            {error, Reason} ->
              error({invalid_option, device_authorization_endpoint, Reason})
          end;
        error ->
          Issuer#{path => <<"/device_authorization">>}
      end
  end.
