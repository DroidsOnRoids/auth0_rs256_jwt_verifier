# frozen_string_literal: true
require "test_helper"

describe Auth0RS256JWTVerifier do
  it "verifies successfully access token" do
    auth0 = Auth0RS256JWTVerifier.new(
      issuer:       "https://multi-jobbers.eu.auth0.com/",
      audience:     "https://multijobbers.herokuapp.com/",
      jwks_url:     "https://multi-jobbers.eu.auth0.com/.well-known/jwks.json",
      http:         http_stub,
      exp_verifier: exp_verifier_stub,
    )

    verification_result = auth0.verify(
      "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik5rTkJPRFEzUWpNeFF6WkVOa1" \
      "kzUVVNMk9VTTFSVGMxUTBZMk4wUXdSVGRHTWpkRk9UQkROdyJ9.eyJpc3MiOiJodHRwczo" \
      "vL211bHRpLWpvYmJlcnMuZXUuYXV0aDAuY29tLyIsInN1YiI6IjZwM2tFc0pkOUhteGFxV" \
      "VIwdXN3c1VFRUdoZTNuQ05IQGNsaWVudHMiLCJhdWQiOiJodHRwczovL211bHRpam9iYmV" \
      "ycy5oZXJva3VhcHAuY29tLyIsImV4cCI6MTQ5NzE4MTMzNSwiaWF0IjoxNDk3MDk0OTM1L" \
      "CJzY29wZSI6IiJ9.LPtyDb26UxS5NKHEU2VJdmj7pDI4-tfgue2Ttk62H0a9XehsCArwwy" \
      "QtI2ZAXxY8gQGS4dhXpcDqevmpfAy9zcjMEvvjWqmcGpepL8bn4MUJ_lAmL3A3FJXduf8T" \
      "pHRXUHiMcdGT0vcFrv5kkMHDzTiwvOUxPcRT5nufX16Vqg3MTQS5pDb2NPcLCqI4PrJhse" \
      "uJnDthxYelUvf6AIyVesuK5e3g8FLiXjZoPmwr3u6xeljF2KECetBPskKI8MgWrhIDD9Zv" \
      "-O_fV1UZ41M-7zURcsQNYV--knHuX0i6nF46JlnbdqoA35d8LJvtnzbiO7hj8mP_GMa8FS" \
      "cKqq5D8w",
    )

    expected_user_id = "6p3kEsJd9HmxaqUR0uswsUEEGhe3nCNH@clients"

    assert verification_result.valid?
    refute verification_result.invalid?
    assert_equal expected_user_id, verification_result.user_id
  end

  it "fails when jwt public key verification is not successful" do
    auth0 = Auth0RS256JWTVerifier.new(
      issuer:       "https://example.eu.auth0.com/",
      audience:     "https://multijobbers.herokuapp.com/",
      jwks_url:     "https://multi-jobbers.eu.auth0.com/.well-known/jwks.json",
      http:         http_stub,
      exp_verifier: exp_verifier_stub,
    )

    verification_result = auth0.verify(
      "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik5rTkJPRFEzUWpNeFF6WkVOa1" \
      "kzUVVNMk9VTTFSVGMxUTBZMk4wUXdSVGRHTWpkRk9UQkROdyJ9.eyJpc3MiOiJodHRwczo" \
      "vL211bHRpLWpvYmJlcnMuZXUuYXV0aDAuY29tLyIsInN1YiI6IjZwM2tFc0pkOUhteGFxV" \
      "VIwdXN3c1VFRUdoZTNuQ05IQGNsaWVudHMiLCJhdWQiOiJodHRwczovL211bHRpam9iYmV" \
      "ycy5oZXJva3VhcHAuY29tLyIsImV4cCI6MTQ5NzQ3NzYyOCwiaWF0IjoxNDk3MzkxMjI4L" \
      "CJzY29wZSI6IiJ9.aGhyzkMM7sE4FNSijzRJlIvJQwx4tBq8uJbL0Taq9I41YOuSWPF4eC" \
      "8886EU3gLkOiEpYlSkX9SHINljHR2ajcNBXoCThbREyReY_ZDjNfXZRREYWT6x8wT5WtmM" \
      "xdxpOOVIXKrxkhfy57vGJs2clpo2MTFEVNPYhslMv-p_WLY",
    )

    refute verification_result.valid?
    assert verification_result.invalid?
  end

  it "fails when jwt is expired" do
    auth0 = Auth0RS256JWTVerifier.new(
      issuer:       "https://multi-jobbers.eu.auth0.com/",
      audience:     "https://multijobbers.herokuapp.com/",
      jwks_url:     "https://multi-jobbers.eu.auth0.com/.well-known/jwks.json",
      http:         http_stub,
      exp_verifier: exp_verifier_stub(expired: true),
    )

    verification_result = auth0.verify(
      "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik5rTkJPRFEzUWpNeFF6WkVOa1" \
      "kzUVVNMk9VTTFSVGMxUTBZMk4wUXdSVGRHTWpkRk9UQkROdyJ9.eyJpc3MiOiJodHRwczo" \
      "vL211bHRpLWpvYmJlcnMuZXUuYXV0aDAuY29tLyIsInN1YiI6IjZwM2tFc0pkOUhteGFxV" \
      "VIwdXN3c1VFRUdoZTNuQ05IQGNsaWVudHMiLCJhdWQiOiJodHRwczovL211bHRpam9iYmV" \
      "ycy5oZXJva3VhcHAuY29tLyIsImV4cCI6MTQ5NzE4MTMzNSwiaWF0IjoxNDk3MDk0OTM1L" \
      "CJzY29wZSI6IiJ9.LPtyDb26UxS5NKHEU2VJdmj7pDI4-tfgue2Ttk62H0a9XehsCArwwy" \
      "QtI2ZAXxY8gQGS4dhXpcDqevmpfAy9zcjMEvvjWqmcGpepL8bn4MUJ_lAmL3A3FJXduf8T" \
      "pHRXUHiMcdGT0vcFrv5kkMHDzTiwvOUxPcRT5nufX16Vqg3MTQS5pDb2NPcLCqI4PrJhse" \
      "uJnDthxYelUvf6AIyVesuK5e3g8FLiXjZoPmwr3u6xeljF2KECetBPskKI8MgWrhIDD9Zv" \
      "-O_fV1UZ41M-7zURcsQNYV--knHuX0i6nF46JlnbdqoA35d8LJvtnzbiO7hj8mP_GMa8FS" \
      "cKqq5D8w",
    )

    refute verification_result.valid?
    assert verification_result.invalid?
  end

  it "fails when jwt is random string" do
    auth0 = Auth0RS256JWTVerifier.new(
      issuer:       "https://multi-jobbers.eu.auth0.com/",
      audience:     "https://multijobbers.herokuapp.com/",
      jwks_url:     "https://multi-jobbers.eu.auth0.com/.well-known/jwks.json",
      http:         http_stub,
      exp_verifier: exp_verifier_stub(expired: true),
    )

    verification_result = auth0.verify("random string")

    refute verification_result.valid?
    assert verification_result.invalid?
  end

  private

  def http_stub
    @http_stub = Object.new
    jwks = sample_jwks
    @http_stub.define_singleton_method(:get) { |*_| jwks }
    @http_stub
  end

  def exp_verifier_stub(expired: false)
    @exp_verifier_stub = Object.new
    @exp_verifier_stub.define_singleton_method(:expired?) { |*_| expired }
    @exp_verifier_stub
  end

  def sample_jwks
    @sample_jwsk ||= File.read("./test/fixtures/sample_jwks.json")
  end
end
