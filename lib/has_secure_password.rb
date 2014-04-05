require 'has_secure_attribute'

module HasSecureAttribute
  def has_secure_password (options = {})
    options   = {
      :attribute    => :password,
      :validations  => true,
      :confirmation => true
    }.merge!(options)
    attribute = options.delete :attribute
    has_secure_attribute(attribute, options)
  end
end
