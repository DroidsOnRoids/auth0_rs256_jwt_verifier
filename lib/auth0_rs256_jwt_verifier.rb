# frozen_string_literal: true
require "http"
require "json"

require "auth0_rs256_jwt_verifier/http_wrapper"
require "auth0_rs256_jwt_verifier/user_id"
require "auth0_rs256_jwt_verifier/results"
require "auth0_rs256_jwt_verifier/jwt_decoder"
require "auth0_rs256_jwt_verifier/jwt_decoder_wrapper"
require "auth0_rs256_jwt_verifier/exp_verifier"
require "auth0_rs256_jwt_verifier/cached_certificates"

class Auth0RS256JWTVerifier
  InvalidHTTPDependencyError = Class.new(RuntimeError)

  def initialize(issuer:, audience:, jwks_url:, http: HTTP, exp_verifier: ExpVerifier.new)
    @audience        = String(audience)
    @issuer          = String(issuer)
    @exp_verifier    = exp_verifier
    @certificates    = CachedCertificates.new(HttpWrapper.new(http), jwks_url)
  end

  def verify(access_token)
    payload = JWTDecoderWrapper.new(
      @audience,
      @issuer,
      @certificates.fetch,
      exp_verifier: @exp_verifier,
      jwt_decoder: JWTDecoder.new,
    ).decode(access_token)
    Results::ValidAccessToken.new(UserId.new(payload.sub))
  rescue JWTDecoderWrapper::Error
    Results::INVALID_ACCESS_TOKEN
  end
end
