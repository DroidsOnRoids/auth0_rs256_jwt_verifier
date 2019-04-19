# frozen_string_literal: true
require "base64"
class Auth0RS256JWTVerifier
  class CertsSet
    NotFoundError = Class.new(RuntimeError)

    def initialize(jwk_set)
      @jwk_set = jwk_set
    end

    def find(id)
      id = String(id)
      cert = certs.find { |c| c.id == id }
      raise NotFoundError, "cert #{id} doesn't exist" if cert.nil?
      cert.cert
    end

    private

    CertWithId = Struct.new(:id, :cert)
    private_constant :CertWithId

    def certs
      @certs ||= @jwk_set.map { |jwk| CertWithId.new(jwk.kid, build_cert(jwk)) }
    end

    def build_cert(jwk)
      encoded = Base64.decode64(String(jwk.x5c.first))
      OpenSSL::X509::Certificate.new(encoded)
    end
  end
  private_constant :CertsSet
end
