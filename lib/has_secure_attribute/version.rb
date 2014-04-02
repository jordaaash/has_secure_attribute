require 'has_secure_attribute/gem_version'

module HasSecureAttribute
  # Returns the version of the currently loaded HasSecureAttribute as a <tt>Gem::Version</tt>
  def self.version
    gem_version
  end
end
