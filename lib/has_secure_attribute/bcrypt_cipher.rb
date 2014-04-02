require 'has_secure_attribute/abstract_cipher'
require 'bcrypt'

module HasSecureAttribute
  class BCryptCipher < AbstractCipher
    attr_reader :options

    def initialize (options = {})
      @options = {
        :cost => 12 # 4..31
      }.merge!(options).freeze
    end

    def digest (secret)
      BCrypt::Password.create(secret, options)
    end

    def authenticate (secret_digest, secret)
      current = BCrypt::Password.new(secret_digest)
      new     = BCrypt::Engine.hash_secret(secret, current.salt, current.cost)
      compare(secret_digest, new)
    end
  end
end
