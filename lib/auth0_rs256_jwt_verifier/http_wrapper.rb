# frozen_string_literal: true
class Auth0RS256JWTVerifier
  class HttpWrapper
    def initialize(http)
      @http = http
    end

    def get(url)
      convert(@http.get(url))
    rescue NoMethodError
      raise InvalidHTTPDependencyError, "#get doesn't defined"
    rescue StandardError => e
      raise InvalidHTTPDependencyError, "#get returned error #{e}"
    end

    private

    def convert(obj)
      obj.to_str
    rescue NoMethodError
      raise InvalidHTTPDependencyError, "#get result must implement #to_str (string)"
    end
  end
  private_constant :HttpWrapper
end
