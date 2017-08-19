# frozen_string_literal: true
require "test_helper"

class Auth0RS256JWTVerifier
  describe JWTDecoderWrapper do
    class JWTDecoderWrapperFake
      def decode(_jwt)
        {}
      end

      def signed_with?(_jwt, _public_key)
        true
      end
    end

    class CertsSetFake
      def find(_id)
        CertFake.new
      end
    end

    class CertFake
      def public_key
        "ascd"
      end
    end

    class ExpVerifierFake
      def expired?(_)
        false
      end
    end

    before :all do
      @decoder      = JWTDecoderWrapperFake.new
      @certs_set    = CertsSetFake.new
      @exp_verifier = ExpVerifierFake.new
      @audience     = "valid audience"
      @issuer       = "valid issuer"

      @jwt_decoder = factory_subject
    end

    it "should execute JWT#decode & JWT#verify with valid args" do
      jwt_str = "JWT to decode"
      public_key = "valid public key"
      cert = Object.new
      cert.define_singleton_method(:public_key) { public_key }

      @decoder = Minitest::Mock.new
      @decoder.expect(:decode, valid_decoded_jwt, [jwt_str])
      @decoder.expect(:signed_with?, valid_decoded_jwt, [jwt_str, public_key])

      @jwt_decoder = factory_subject(jwt_decoder: @decoder)

      @certs_set.stub(:find, cert) do
        @jwt_decoder.decode(jwt_str)
      end

      @decoder.verify
    end

    it "should raise InvalidJWTError if adapter#decode raises standard error" do
      @decoder.stub(:decode, ->(*_) { raise StandardError }) do
        assert_raises(JWTDecoderWrapper::InvalidJWTError) do
          @jwt_decoder.decode("jwt")
        end
      end
    end

    it "should raise InvalidAlgError" do
      @decoder.stub(
        :decode,
        valid_decoded_jwt(alg: "HS256"),
      ) do
        assert_raises(JWTDecoderWrapper::InvalidAlgError) do
          @jwt_decoder.decode("jwt")
        end
      end
    end

    it "should raise CertNotFoundError" do
      @decoder.stub(
        :decode,
        valid_decoded_jwt(kid: "unexisting key"),
      ) do
        @certs_set.stub(
          :find,
          ->(*_) { raise CertsSet::NotFoundError },
        ) do
          assert_raises(JWTDecoderWrapper::CertNotFoundError) do
            @jwt_decoder.decode("jwt")
          end
        end
      end
    end

    it "should raise VerificationError" do
      @decoder.stub(:decode, valid_decoded_jwt) do
        @decoder.stub(:signed_with?, false) do
          assert_raises(JWTDecoderWrapper::VerificationError) do
            @jwt_decoder.decode("jwt")
          end
        end
      end
    end

    it "should raise VerificationError if adapter#signed_with raises StandardError" do
      @decoder.stub(:decode, valid_decoded_jwt) do
        @decoder.stub(:signed_with?, ->(*_) { raise StandardError }) do
          assert_raises(JWTDecoderWrapper::VerificationError) do
            @jwt_decoder.decode("jwt")
          end
        end
      end
    end

    it "should raise missing exp error" do
      @decoder.stub(
        :decode,
        valid_decoded_jwt.reject { |k, _| k == :exp },
      ) do
        assert_raises(JWTDecoderWrapper::MissingExpError) do
          @jwt_decoder.decode("jwt")
        end
      end
    end

    it "should raise invalid exp error" do
      @decoder.stub(
        :decode,
        valid_decoded_jwt(exp: "1234"),
      ) do
        assert_raises(JWTDecoderWrapper::InvalidExpError) do
          @jwt_decoder.decode("jwt")
        end
      end
    end

    it "should raise jwt expired error" do
      @decoder.stub(
        :decode,
        valid_decoded_jwt(exp: 1234),
      ) do
        @exp_verifier.stub(:expired?, true) do
          assert_raises(JWTDecoderWrapper::JWTExpiredError) do
            @jwt_decoder.decode("jwt")
          end
        end
      end
    end

    it "should raise invalid audience error" do
      @decoder.stub(
        :decode,
        valid_decoded_jwt(aud: "invalid audience"),
      ) do
        assert_raises(JWTDecoderWrapper::InvalidAudienceError) do
          @jwt_decoder.decode("jwt")
        end
      end
    end

    it "should raise invalid issuer error" do
      @decoder.stub(
        :decode,
        valid_decoded_jwt(iss: "invalid issuer"),
      ) do
        assert_raises(JWTDecoderWrapper::InvalidIssuerError) do
          @jwt_decoder.decode("jwt")
        end
      end
    end

    it "should raise missing sub error" do
      @decoder.stub(
        :decode,
        valid_decoded_jwt.reject { |k, _| k == :sub },
      ) do
        assert_raises(JWTDecoderWrapper::MissingSubError) do
          @jwt_decoder.decode("jwt")
        end
      end
    end

    it "should raise invalid sub error" do
      @decoder.stub(
        :decode,
        valid_decoded_jwt(sub: { id: 1 }),
      ) do
        assert_raises(JWTDecoderWrapper::InvalidSubError) do
          @jwt_decoder.decode("jwt")
        end
      end
    end

    it "should raise nothing and return payload with sub" do
      sub = "sub1234"
      @decoder.stub(
        :decode,
        valid_decoded_jwt(sub: sub),
      ) do
        begin
          payload = @jwt_decoder.decode("jwt")
          assert_respond_to payload, :sub
          assert_equal sub, payload.sub
        rescue StandardError => e
          refute "expected to not return any error buty got #{e}"
        end
      end
    end

    private

    def factory_subject(dependencies = {})
      default_dependencies = {
        exp_verifier: @exp_verifier,
        jwt_decoder:  @decoder,
      }
      JWTDecoderWrapper.new(
        @audience, @issuer, @certs_set,
        default_dependencies.merge(dependencies)
      )
    end

    def valid_decoded_jwt(overwrites = {})
      {
        alg: "RS256",
        kid: "id1",
        exp: 1234,
        aud: @audience,
        iss: @issuer,
        sub: "1234",
      }.merge(overwrites)
    end
  end
end
