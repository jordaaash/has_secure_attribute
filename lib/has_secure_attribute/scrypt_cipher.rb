require 'has_secure_attribute/abstract_cipher'
require 'scrypt'

module HasSecureAttribute
  class SCryptCipher < AbstractCipher
    attr_reader :options

    def initialize (options = {})
      @options = {
        :key_len     => 256,  # bytes,          16..512
        :salt_size   => 32,   # bytes,           8..32
        :max_time    => 0.25, # seconds,         0..Infinity?
        :max_mem     => 0,    # bytes, (1024*1024)..Infinity?
        :max_memfrac => 0     # fraction,        0..0.5
      }.merge!(options).freeze
    end

    def digest (secret)
      SCrypt::Password.create(secret, options)
    end

    def authenticate (secret_digest, secret)
      current    = SCrypt::Password.new(secret_digest)
      salt       = current.cost + current.salt
      key_length = current.hash.length / 2
      new        = SCrypt::Engine.hash_secret(secret, salt, key_length)
      compare(secret_digest, new)
    end
  end
end
