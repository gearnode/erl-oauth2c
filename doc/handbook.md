# Introduction
This document contains development notes about the `oauth2c` library.

# Versioning
The following `oauth2c` versions are available:
- `0.y.z` unstable versions.
- `x.y.z` stable versions: `oauth2c` will maintain reasonable backward
  compatibility, deprecating features before removing them.
- Experimental untagged versions.

Developers who use unstable or experimental versions are responsible for
updating their application when `oauth2c` is modified. Note that
unstable versions can be modified without backward compatibility at any
time.

# Supported Grants
## Authorization Code Grant
Example:
```erlang
1> Issuer = <<"https://example.okta.com">>,
   Id = <<"my_client_id">>,
   Secret = <<"my_very_secret_paswd">>,
   {ok, Client} =
     oauth2c:new_client(Issuer, Id, Secret, #{discovery => true}).
     
2> AuthorizeRequest = #{redirect_uri => <<"http://example.com">>,
                        state => <<"foobar">>},
   {ok, Redirect} =
     oauth2c:authorize_url(Client, <<"code">>, AuthorizeRequest).

3> TokenRequest = #{code => <<"some code">>,
                    redirect_uri => <<"http://example.com">>},
   {ok, Token} =
     oauth2c:token(Client, <<"authorization_code">>, TokenRequest).
```

## Implicit Grant
Example:
```erlang
1> Issuer = <<"https://example.okta.com">>,
   Id = <<"my_client_id">>,
   Secret = <<"my_very_secret_paswd">>,
   {ok, Client} =
     oauth2c:new_client(Issuer, Id, Secret, #{discovery => true}).
     
2> AuthorizeRequest = #{redirect_uri => <<"http://example.com">>,
                        state => <<"foobar">>},
   {ok, Redirect} =
     oauth2c:authorize_url(Client, <<"token">>, AuthorizeRequest).
```

## Resource Owner Password Credentials Grant
Example:
```erlang
1> Issuer = <<"https://example.okta.com">>,
   Id = <<"my_client_id">>,
   Secret = <<"my_very_secret_paswd">>,
   {ok, Client} =
     oauth2c:new_client(Issuer, Id, Secret, #{discovery => true}).
     
2> TokenRequest = #{username => <<"john.doe">>,
                    password => <<"my secure password">>},
   {ok, Token} =
     oauth2c:token(Client, <<"password">>, TokenRequest).
```

## Client Credentials Grant
Example:
```erlang
1> Issuer = <<"https://example.okta.com">>,
   Id = <<"my_client_id">>,
   Secret = <<"my_very_secret_paswd">>,
   {ok, Client} =
     oauth2c:new_client(Issuer, Id, Secret, #{discovery => true}).
     
2> TokenRequest = #{},
   {ok, Token} =
     oauth2c:token(Client, <<"client_credentials">>, TokenRequest).
```

# Introspection
Example:
```erlang
1> Issuer = <<"https://example.okta.com">>,
   Id = <<"my_client_id">>,
   Secret = <<"my_very_secret_paswd">>,
   {ok, Client} =
     oauth2c:new_client(Issuer, Id, Secret, #{discovery => true}).

2> {ok, Introspect} =
     oauth2c:introspect(Client, #{token => <<"my access token">>}).
```

# Revocation
Example:
```erlang
1> Issuer = <<"https://example.okta.com">>,
   Id = <<"my_client_id">>,
   Secret = <<"my_very_secret_paswd">>,
   {ok, Client} =
     oauth2c:new_client(Issuer, Id, Secret, #{discovery => true}).

2> ok = oauth2c:revoke(Client, #{token => <<"my access token">>}).
```
# Discovery
