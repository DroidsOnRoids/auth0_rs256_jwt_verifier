[![Build Status](https://travis-ci.org/DroidsOnRoids/auth0_rs256_jwt_verifier.svg?branch=master)](https://travis-ci.org/DroidsOnRoids/auth0_rs256_jwt_verifier)

# Auth0 JWT (RS256) verification library 
[Auth0](https://auth0.com) is web service handling users identities which can be easily plugged
into your application. It provides [SDKs](https://auth0.com/docs) for many languages which enable you to sign up/in users
and returns access token ([JWT](https://jwt.io)) in exchange. Access token can be used then to access your's Web Service.
This gem helps you to [verify](https://auth0.com/docs/api-auth/tutorials/verify-access-token#verify-the-signature)
such access token which has been signed using the RS256 algorithm.

## Installation
Install the `auth0_rs256_jwt_verifier` package from [Rubygems](https://rubygems.org/gems/auth0_rs256_jwt_verifier):

```bash
    gem install auth0_rs256_jwt_verifier 
```

Install it using [Bundler](https://bundler.io/) specifying it as dependency in your Gemfile:

```ruby
    gem "auth0_rs256_jwt_verifier"
```

## Usage

```ruby
# Verifier caches RS256 certificates fetched from jwks_uri.
# You should initialize it once and reuse for JWTs verification.

require "auth0_rs256_jwt_verifier"

AUTH0_JWT_VERIFIER = Auth0RS256JWTVerifier.new(
  issuer:   "ISSUER",
  audience: "AUDIENCE",
  jwks_url: "https://YOUR_AUTH0_DOMAIN/.well-known/jwks.json"
)

if AUTH0_JWT_VERIFIER.verify("JWT_ACCESS_TOKEN_SIGNED_USING_RS256_ALGORITHM").valid?
  # handle valid access token
else
  # handle invalid access token
end
```
