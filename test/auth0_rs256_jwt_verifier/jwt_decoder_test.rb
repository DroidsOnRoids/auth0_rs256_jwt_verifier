# frozen_string_literal: true
require "test_helper"

class Auth0RS256JWTVerifier
  describe JWTDecoder do
    before :each do
      @decoder = JWTDecoder.new
    end

    it "should decode simple jwt" do
      jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImlkMTIzNCJ9." \
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjoiYXVkaWVuY2UiLCJpc3MiO" \
            "iJpc3N1ZXIifQ.cp374RbcG-q8rTLxSoWtLK7dtn5cBa3_g4riKL9OSt0"
      result = @decoder.decode(jwt)
      assert_equal "HS256",    result[:alg]
      assert_equal "id1234",   result[:kid]
      assert_equal "audience", result[:aud]
      assert_equal "issuer",   result[:iss]
    end
  end
end
