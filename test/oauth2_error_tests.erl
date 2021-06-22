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

-module(oauth2_error_tests).

-include_lib("eunit/include/eunit.hrl").

parse_test_() ->
  [?_assertMatch({error, {invalid_syntax, _}},
                 oauth2c_error:parse(<<>>)),
   ?_assertMatch({error, {invalid_object, _}},
                 oauth2c_error:parse(<<"{}">>)),
   ?_assertEqual({ok, #{error => <<"invalid_request">>}},
                 oauth2c_error:parse(<<"{\"error\":\"invalid_request\"}">>)),
   ?_assertEqual({ok,
                  #{error => <<"invalid_request">>,
                    error_description =>
                      <<"Request was missing the 'redirect_uri' parameter.">>,
                    error_uri =>
                      #{host => <<"authorization-server.com">>,
                        path => <<"/docs/access_token">>,
                        scheme => <<"https">>}}},
                 oauth2c_error:parse(<<"{\"error\":\"invalid_request\",\"error_description\":\"Request was missing the 'redirect_uri' parameter.\",\"error_uri\":\"https://authorization-server.com/docs/access_token\"}">>))].
