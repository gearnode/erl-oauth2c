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

-module(oauth2_client_tests).

-include_lib("eunit/include/eunit.hrl").

new_client_3_test_() ->
  Issuer = <<"https://example.com">>,
  Id = <<"my_client_id">>,
  Secret = <<"my_client_secret">>,
  [?_assertEqual({ok,
                  #{authorization_endpoint =>
                      #{host => <<"example.com">>,
                        path => <<"/authorize">>,scheme => <<"https">>},
                    device_authorization_endpoint =>
                      #{host => <<"example.com">>,
                        path => <<"/device_authorization">>,
                        scheme => <<"https">>},
                    discovery => #{},
                    id => <<"my_client_id">>,
                    introspection_endpoint =>
                      #{host => <<"example.com">>,
                        path => <<"/introspect">>,scheme => <<"https">>},
                    issuer =>
                      #{host => <<"example.com">>,scheme => <<"https">>},
                    revocation_endpoint =>
                      #{host => <<"example.com">>,path => <<"/revoke">>,
                        scheme => <<"https">>},
                    secret => <<"my_client_secret">>,
                    token_endpoint =>
                      #{host => <<"example.com">>,path => <<"/token">>,
                        scheme => <<"https">>}}},
                 oauth2c_client:new_client(Issuer, Id, Secret)),
   ?_assertEqual(oauth2c_client:new_client(Issuer, Id, Secret),
                 oauth2c_client:new_client(Issuer, Id, Secret, #{}))].

new_client_4_test_() ->
  Issuer = <<"https://example.com">>,
  Id = <<"my_client_id">>,
  Secret = <<"my_client_secret">>,
  Options = #{authorization_endpoint =>
                <<"https://example.com/auth">>,
              token_endpoint =>
                <<"https://example.com/access_token">>,
              introspection_endpoint =>
                <<"https://example.com/explain">>,
              revocation_endpoint =>
                <<"https://example.com/delete">>,
              device_authorization_endpoint =>
                <<"https://example.com/console">>},
  Options2 = #{authorization_endpoint =>
                 #{host => <<"example.com">>, path => <<"/auth">>,
                   scheme => <<"https">>},
               token_endpoint =>
                 #{host => <<"example.com">>, path => <<"/access_token">>,
                   scheme => <<"https">>},
               introspection_endpoint =>
                 #{host => <<"example.com">>, path => <<"/explain">>,
                   scheme => <<"https">>},
               revocation_endpoint =>
                 #{host => <<"example.com">>, path => <<"/delete">>,
                   scheme => <<"https">>},
               device_authorization_endpoint =>
                 #{host => <<"example.com">>, path => <<"/console">>,
                   scheme => <<"https">>}},
  [?_assertEqual({ok,
                  #{authorization_endpoint =>
                      #{host => <<"example.com">>,path => <<"/auth">>,
                        scheme => <<"https">>},
                    device_authorization_endpoint =>
                      #{host => <<"example.com">>,path => <<"/console">>,
                        scheme => <<"https">>},
                    discovery => #{},
                    id => <<"my_client_id">>,
                    introspection_endpoint =>
                      #{host => <<"example.com">>,path => <<"/explain">>,
                        scheme => <<"https">>},
                    issuer =>
                      #{host => <<"example.com">>,scheme => <<"https">>},
                    revocation_endpoint =>
                      #{host => <<"example.com">>,path => <<"/delete">>,
                        scheme => <<"https">>},
                    secret => <<"my_client_secret">>,
                    token_endpoint =>
                      #{host => <<"example.com">>,
                        path => <<"/access_token">>,
                        scheme => <<"https">>}}},
                 oauth2c_client:new_client(Issuer, Id, Secret, Options)),
   ?_assertEqual({ok,
                  #{authorization_endpoint =>
                      #{host => <<"example.com">>,path => <<"/auth">>,
                        scheme => <<"https">>},
                    device_authorization_endpoint =>
                      #{host => <<"example.com">>,path => <<"/console">>,
                        scheme => <<"https">>},
                    discovery => #{},
                    id => <<"my_client_id">>,
                    introspection_endpoint =>
                      #{host => <<"example.com">>,path => <<"/explain">>,
                        scheme => <<"https">>},
                    issuer =>
                      #{host => <<"example.com">>,scheme => <<"https">>},
                    revocation_endpoint =>
                      #{host => <<"example.com">>,path => <<"/delete">>,
                        scheme => <<"https">>},
                    secret => <<"my_client_secret">>,
                    token_endpoint =>
                      #{host => <<"example.com">>,
                        path => <<"/access_token">>,
                        scheme => <<"https">>}}},
                 oauth2c_client:new_client(Issuer, Id, Secret, Options2))].
