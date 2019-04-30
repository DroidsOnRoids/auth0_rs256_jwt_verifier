# frozen_string_literal: true
class Auth0RS256JWTVerifier
  class CachedCertificates
    class JWK
      ParseError = Class.new(RuntimeError)

      def initialize(hash)
        raise ParseError unless hash.is_a?(Hash)
        %i(Alg Kty Use X5C N E Kid X5T).each do |field_name|
          field = self.class.const_get(field_name).new(hash[String(field_name).downcase])
          instance_variable_set("@#{String(field_name).downcase}", field)
        end
      end

      attr_reader :alg, :kty, :use, :x5c, :n, :e, :kid, :x5t

      def inspect
        "JWK(\n"                    \
        "\talg: #{@alg},\n"         \
        "\tkty: #{@kty},\n"         \
        "\tuse: #{@use},\n"         \
        "\tx5c: #{@x5c.inspect.split("\n").map { |l| "\t#{l}" }.join("\n")},\n" \
        "\tn: #{@n},\n"             \
        "\te: #{@e},\n"             \
        "\tkid: #{@kid},\n"         \
        "\tx5t: #{@x5t}\n"          \
        ")"
      end

      class OptionalStringJWKMember
        include Comparable

        def initialize(value)
          if value.nil?
            @value = nil
          elsif value.is_a?(String)
            @value = value
          else
            raise ParseError, "require field #{self.class.name} to be String but is '#{value}'"
          end
        end

        def <=>(other)
          @value <=> String(other)
        end

        def to_s
          @value
        end

        def present?
          !@value.nil?
        end
      end
      private_constant :OptionalStringJWKMember

      class RequiredStringJWKMember
        include Comparable

        def initialize(value)
          if value.is_a?(String)
            @value = value
          elsif value.nil?
            raise PraseError, "field #{self.class.name} is required"
          else
            raise ParseError, "require field #{self.class.name} to be String but is '#{value}'"
          end
        end

        def <=>(other)
          @value <=> String(other)
        end

        def to_s
          @value
        end

        def present?
          true
        end
      end
      private_constant :RequiredStringJWKMember

      Kty = Class.new(RequiredStringJWKMember)
      Use = Class.new(OptionalStringJWKMember)
      Alg = Class.new(OptionalStringJWKMember)
      N   = Class.new(OptionalStringJWKMember)
      E   = Class.new(OptionalStringJWKMember)
      Kid = Class.new(OptionalStringJWKMember)
      X5T = Class.new(OptionalStringJWKMember)

      class X5C
        include Enumerable

        class Certificate
          def initialize(certificate)
            raise ParseError unless certificate.is_a?(String)
            @certificate = certificate
          end

          def to_s
            @certificate
          end

          def to_str
            to_s
          end
        end

        def initialize(certificates)
          if certificates.nil?
            @certificates = nil
          else
            raise ParseError unless certificates.is_a?(Array)
            @certificates = certificates.map { |certificate| Certificate.new(certificate) }
          end
        end

        def inspect
          "X5C(\n#{@certificates.map { |c| "\t#{c}" }.join(",\n")}\n\t)"
        end

        def present?
          !@certificates.nil?
        end

        def each
          return unless present?
          @certificates.each { |cert| yield cert }
        end
      end
    end
    private_constant :JWK
  end
end
