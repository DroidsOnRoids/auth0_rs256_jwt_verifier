# frozen_string_literal: true
require "http"
require "json"

require "auth0_jwt_rs256_verifier/user_id"
require "auth0_jwt_rs256_verifier/results"
require "auth0_jwt_rs256_verifier/jwt_decoder"
require "auth0_jwt_rs256_verifier/jwt_decoder_wrapper"
require "auth0_jwt_rs256_verifier/jwk_set_downloader"
require "auth0_jwt_rs256_verifier/valid_jwk_set"
require "auth0_jwt_rs256_verifier/certs_set"
require "auth0_jwt_rs256_verifier/exp_verifier"
require "auth0_jwt_rs256_verifier/jwk"

class Auth0RS256JWTVerifier
  def initialize(issuer:, audience:, jwks_url:, http: HTTP, exp_verifier: ExpVerifier.new)
    @audience        = audience
    @issuer          = issuer
    @jwks_url        = jwks_url
    @jwks_downloader = JWKSetDownloader.new(http)
    @exp_verifier    = exp_verifier
    @certificates    = nil
  end

  def verify(access_token)
    payload = JWTDecoderWrapper.new(
      @audience,
      @issuer,
      certificates,
      exp_verifier: @exp_verifier,
      jwt_decoder: JWTDecoder.new,
    ).decode(access_token)
    Results::ValidAccessToken.new(UserId.new(payload.sub))
  rescue JWTDecoderWrapper::Error
    Results::INVALID_ACCESS_TOKEN
  end

  private

  def certificates
    return @certificates if @certificates
    @certificates = CertsSet.new(ValidJWKSet.new(@jwks_downloader.download(@jwks_url)))
  end
end
