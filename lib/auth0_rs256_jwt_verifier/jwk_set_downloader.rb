# frozen_string_literal: true
class Auth0RS256JWTVerifier
  class JWKSetDownloader
    InvalidJWKSetError = Class.new(RuntimeError)

    class JWKSet
      include Enumerable

      ParseError = Class.new(RuntimeError)

      def initialize(hash)
        raise ParseError if hash["keys"].is_a?(Hash)
        @keys = hash["keys"].map { |key| JWK.new(key) }
      end

      def each
        @keys.each { |key| yield key }
      end

      def inspect
        "JWKSet(#{@keys.collect(&:inspect).join(", ")})"
      end
    end
    private_constant :JWKSet

    def initialize(http)
      @http = http
    end

    def download(url)
      body = @http.get(url)
      json = JSON.parse(body)
      begin
        JWKSet.new(json)
      rescue JWKSet::ParseError
        raise InvalidJWKSetError
      end
    end
  end
  private_constant :JWKSetDownloader
end
