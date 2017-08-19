# frozen_string_literal: true
class Auth0RS256JWTVerifier
  module Results
    class Base
      def valid?
        raise NotImplementedMethod
      end

      def invalid?
        !valid?
      end

      def on(_)
        raise NotImplementedMethod
      end
    end
    private_constant :Base

    class ValidAccessToken < Base
      def initialize(user_id)
        @user_id = user_id
      end

      attr_reader :user_id

      def valid?
        true
      end

      def on(type)
        yield @user_id if type == :valid
        self
      end

      def inspect
        "Auth0RS256JWTVerifier::Results::ValidAccessToken(user_id: #{@user_id})"
      end
    end

    INVALID_ACCESS_TOKEN = Class.new(Base) do
      def valid?
        false
      end

      def on(type)
        yield if type == :invalid
        self
      end

      def inspect
        "Auth0RS256JWTVerifier::Results::INVALID_ACCESS_TOKEN"
      end
    end.new.freeze
  end
  private_constant :Results
end
