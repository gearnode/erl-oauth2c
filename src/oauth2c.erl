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

-export([new_client/3, new_client/4]).

-export_type([error_code/0, error_description/0, error_response/0,
              client/0, issuer/0]).

-type error_code() :: invalid_request
                    | invalid_client
                    | invalid_grant
                    | unauthorized_client
                    | unsupported_grant_type
                    | invalid_scope
                    | binary().

-type error_description() :: binary().

-type error_response() :: #{error := error_code(),
                            error_description => error_description(),
                            error_uri => uri:uri()}.

-type client_id() :: binary().
-type client_secret() :: binary().
-type issuer() :: binary().

-type client() :: #{issuer := issuer(),
                    id := client_id(),
                    secret := client_secret()}.

%% TODO: change returns type of the new_client/3 and new_client/4

-spec new_client(issuer(), client_id(), client_secret()) ->
        term().
new_client(Issuer, Id, Secret) ->
  new_client(Issuer, Id, Secret, #{}).

-spec new_client(issuer(), client_id(), client_secret(), Options) ->
        term()
          when Options :: #{issuer => binary(),
                            authorize_url => binary(),
                            token_url => binary()}.
new_client(Issuer, Id, Secret, Options) ->
  %% TODO: returns an error when the authorize_url or token_url begin with "/"
  %% as it's override the issuer.
  Client = #{issuer => Issuer,
             id => Id,
             secret => Secret,
             authorize_url =>
               uri_string:resolve(
                 maps:get(authorize_url, Options, <<"authorize">>),
                 Issuer),
             token_url =>
               uri_string:resolve(
                 maps:get(token_url, Options, <<"token">>),
                 Issuer)},
  {ok, Client}.
