# frozen_string_literal: true
Gem::Specification.new do |s|
  s.name          = "auth0_rs256_jwt_verifier"
  s.version       = "0.0.1"
  s.date          = "2017-06-12"
  s.summary       = "Auth0 JWT (RS256) verification library"
  s.description   = <<-DESCRIPTION.gsub(/\s+/, " ").strip
                      Auth0 (https://auth0.com) is web service handling users identities which can be easily plugged
                      into your application. It provides SDKs for many languages which enable you to sign up/in users
                      and returns access token (JWT) in exchange. Access token can be used then to access your's Web Service.
                      This gem helps you to verify
                      (https://auth0.com/docs/api-auth/tutorials/verify-access-token#verify-the-signature)
                      such access token which has been signed using the RS256 algorithm.
                    DESCRIPTION
  s.authors       = ["Krzysztof Zielonka"]
  s.email         = "krzysztof.zielonka@droidsonroids.pl"
  s.license       = "MIT"
  s.homepage      = "https://github.com/DroidsOnRoids/auth0_rs256_jwt_verifier"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test}/*`.split("\n")
  s.require_paths = ["lib"]

  s.required_ruby_version = ">= 2.2.0"

  s.add_runtime_dependency "http", "~> 2"
  s.add_runtime_dependency "json-jwt", "~> 1.7"

  s.add_development_dependency "rake", "~> 12"
  s.add_development_dependency "minitest", "~> 5"
end
