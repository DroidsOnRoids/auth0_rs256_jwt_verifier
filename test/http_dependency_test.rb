# frozen_string_literal: true
require "test_helper"

describe Auth0RS256JWTVerifier do
  it "raises error if provided http dependency doesn't have get method" do
    http = Object.new

    auth0 = factory_verificator(http)

    assert_raises(Auth0RS256JWTVerifier::InvalidHTTPDependencyError) do
      auth0.verify("token")
    end
  end

  it "raises error if provided http dependency raises any error" do
    http = Object.new
    http.define_singleton_method(:get) do |*_|
      raise RuntimeError
    end

    auth0 = factory_verificator(http)

    assert_raises(Auth0RS256JWTVerifier::InvalidHTTPDependencyError) do
      auth0.verify("token")
    end
  end

  it "raises error if provided http dependency doesn't return string" do
    http = Object.new
    http.define_singleton_method(:get) { |*_| Object.new }

    auth0 = factory_verificator(http)

    assert_raises(Auth0RS256JWTVerifier::InvalidHTTPDependencyError) do
      auth0.verify("token")
    end
  end

  private

  def factory_verificator(http)
    Auth0RS256JWTVerifier.new(
      issuer:       "https://multi-jobbers.eu.auth0.com/",
      audience:     "https://multijobbers.herokuapp.com/",
      jwks_url:     "https://multi-jobbers.eu.auth0.com/.well-known/jwks.json",
      http:         http,
      exp_verifier: Object.new,
    )
  end
end
