# frozen_string_literal: true
class Auth0RS256JWTVerifier
  class JWTDecoderWrapper
    Payload = Struct.new(:sub)
    private_constant :Payload

    Error                = Class.new(RuntimeError)
    InvalidJWTError      = Class.new(Error)
    InvalidAlgError      = Class.new(Error)
    InvalidAudienceError = Class.new(Error)
    InvalidIssuerError   = Class.new(Error)
    MissingSubError      = Class.new(Error)
    InvalidSubError      = Class.new(Error)
    VerificationError    = Class.new(Error)
    MissingExpError      = Class.new(Error)
    InvalidExpError      = Class.new(Error)
    JWTExpiredError      = Class.new(Error)
    CertNotFoundError    = Class.new(Error)

    def initialize(audience, issuer, certificates, exp_verifier:, jwt_decoder:)
      @audience     = audience
      @issuer       = issuer
      @certificates = certificates
      @exp_verifier = exp_verifier
      @jwt_decoder  = jwt_decoder
    end

    def decode(jwt_str)
      jwt_str = String(jwt_str)

      decoded_jwt = raw_decode(jwt_str)

      verify_alg(decoded_jwt)

      public_key = find_public_key_for(decoded_jwt)
      verify_is_signed(jwt_str, public_key)

      # verify JWT
      verify_expiration_time(decoded_jwt)
      verify_audience(decoded_jwt)
      verify_issuer(decoded_jwt)
      verify_sub(decoded_jwt)

      Payload.new(decoded_jwt[:sub])
    end

    private

    def raw_decode(jwt_str)
      @jwt_decoder.decode(jwt_str)
    rescue StandardError => e
      raise InvalidJWTError, e.message
    end

    def verify_alg(decoded_jwt)
      alg = decoded_jwt[:alg]
      raise InvalidAlgError, "alg should be RS256 but is #{alg}" unless alg == "RS256"
    end

    def find_public_key_for(decoded_jwt)
      kid = decoded_jwt[:kid]
      cert = @certificates.find(kid)
      raise CertNotFoundError, "cert #{kid} not found" if cert == :not_found
      cert.public_key
    end

    def verify_is_signed(jwt_str, public_key)
      raise VerificationError unless @jwt_decoder.signed_with?(jwt_str, public_key)
    rescue StandardError => e
      raise VerificationError, e.message
    end

    def verify_expiration_time(decoded_jwt)
      verify_exp_exist(decoded_jwt)
      verify_exp_is_int(decoded_jwt)
      raise JWTExpiredError, "jwt expired" if @exp_verifier.expired?(decoded_jwt[:exp])
    end

    def verify_exp_exist(decoded_jwt)
      raise MissingExpError, "missing 'exp' jwt key" unless decoded_jwt.key?(:exp)
    end

    def verify_exp_is_int(decoded_jwt)
      return if decoded_jwt[:exp].is_a?(Integer)
      raise InvalidExpError, "jwt 'exp' field must be an integer"
    end

    def verify_audience(decoded_jwt)
      raise InvalidAudienceError unless Array(decoded_jwt[:aud]).include?(@audience)
    end

    def verify_issuer(decoded_jwt)
      raise InvalidIssuerError unless decoded_jwt[:iss] == @issuer
    end

    def verify_sub(decoded_jwt)
      raise MissingSubError unless decoded_jwt.key?(:sub)
      raise InvalidSubError unless decoded_jwt[:sub].is_a?(String)
    end
  end
  private_constant :JWTDecoderWrapper
end
