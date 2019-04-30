# frozen_string_literal: true
require_relative "./cached_certificates/jwk_set_downloader"
require_relative "./cached_certificates/certs_set"
require_relative "./cached_certificates/valid_jwk_set"
require_relative "./cached_certificates/jwk"

class Auth0RS256JWTVerifier
  class CachedCertificates
    def initialize(http, jwks_url)
      @jwks_downloader = JWKSetDownloader.new(http)
      @jwks_url = String(jwks_url)

      @certificates = :not_fetched_yet
    end

    def fetch
      return @certificates if fetched?
      @certificates = download_cert
    end

    private

    def fetched?
      @certificates != :not_fetched_yet
    end

    def download_cert
      CertsSet.new(ValidJWKSet.new(@jwks_downloader.download(@jwks_url)))
    end
  end
  private_constant :CachedCertificates
end
