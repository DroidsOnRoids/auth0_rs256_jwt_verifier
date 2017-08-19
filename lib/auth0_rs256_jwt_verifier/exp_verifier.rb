# frozen_string_literal: true
class Auth0RS256JWTVerifier
  class ExpVerifier
    def expired?(exp)
      Time.at(exp).utc < Time.now.utc
    end
  end
end
