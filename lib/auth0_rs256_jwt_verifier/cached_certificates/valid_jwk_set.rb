# frozen_string_literal: true
class Auth0RS256JWTVerifier
  class CachedCertificates
    class ValidJWKSet
      include Enumerable

      def initialize(jwk_set)
        @jwk_set = jwk_set
      end

      def each
        filtered_jwk_set.each { |jwk| yield jwk }
      end

      private

      def filtered_jwk_set
        @filtered ||= @jwk_set.select { |jwk| valid_jwk?(jwk) }
      end

      def valid_jwk?(jwk)
        jwk.use == "sig" &&
          jwk.kty == "RSA" &&
          jwk.kid.present? &&
          jwk.x5c.any?
      end
    end
    private_constant :ValidJWKSet
  end
end
