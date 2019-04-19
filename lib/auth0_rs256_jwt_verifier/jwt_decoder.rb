# frozen_string_literal: true
require "json/jwt"

class Auth0RS256JWTVerifier
  class JWTDecoder
    def decode(jwt_str)
      jwt = JSON::JWT.decode(jwt_str, :skip_verification)
      DecodedJWT.new(jwt)
    end

    def signed_with?(jwt_str, public_key)
      jwt_str = String(jwt_str)
      JSON::JWT.decode(jwt_str, public_key)
      true
    rescue JSON::JWS::VerificationFailed
      false
    end

    class DecodedJWT
      def initialize(jwt)
        @jwt = jwt
      end

      def [](k)
        case k
        when :alg then @jwt.alg
        when :kid then @jwt.header[:kid]
        else @jwt[k]
        end
      end

      def key?(k)
        ![k].nil?
      end
    end
    private_constant :DecodedJWT
  end
  private_constant :JWTDecoder
end
