# frozen_string_literal: true
class Auth0RS256JWTVerifier
  class UserId
    def initialize(id)
      @id = String(id).dup.freeze
    end

    def to_s
      @id
    end

    def to_str
      to_s
    end

    def ==(other)
      String(self) == String(other)
    end

    def inspect
      "Auth0RS256JWTVerifier::UserId(#{@id})"
    end
  end
  private_constant :UserId
end
