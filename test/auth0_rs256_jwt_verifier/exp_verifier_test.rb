# frozen_string_literal: true
require "test_helper"

class Auth0RS256JWTVerifier
  describe ExpVerifier do
    before :each do
      @verificator = ExpVerifier.new
    end

    it "classifies value 0 as expired time" do
      assert @verificator.expired?(0)
    end

    it "classifies future time as not expired" do
      one_hour_from_now = (Time.now + 3600).to_i
      refute @verificator.expired?(one_hour_from_now)
    end
  end
end
