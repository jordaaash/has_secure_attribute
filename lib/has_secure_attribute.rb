require 'has_secure_attribute/version'
require 'active_support/dependencies/autoload'
require 'active_record/base'

module HasSecureAttribute
  extend ActiveSupport::Autoload

  autoload :AbstractCipher
  autoload :BCryptCipher, 'has_secure_attribute/bcrypt_cipher'
  autoload :SCryptCipher, 'has_secure_attribute/scrypt_cipher'

  def has_secure_attribute (attribute, options = {})
    options           = {
      :validations       => false,
      :confirmation      => false,
      :column            => nil,
      :cipher            => nil,
      :current_attribute => nil,
      :new_attribute     => nil
    }.merge!(options)
    column            = options[:column] || :"#{attribute}_digest"
    cipher            = options[:cipher] || SCryptCipher.new
    validations       = options[:validations]
    confirmation      = options[:confirmation]
    current_attribute = options[:current_attribute] || :"current_#{attribute}"
    new_attribute     = options[:new_attribute] || :"new_#{attribute}"
    attribute_change  = :"#{attribute}_change"

    attr_reader attribute
    define_method :"#{attribute}=" do |value|
      digest = value.blank? ? nil : cipher.digest(value)
      public_send :"#{column}=", digest
      instance_variable_set :"@#{attribute}", value
    end

    define_method :authenticate do |value, validation_attribute = nil|
      value_digest = public_send column
      if cipher.authenticate(value_digest, value)
        true
      else
        if validation_attribute
          error = value.blank? ? :blank : :invalid
          errors.add(validation_attribute, error)
        end
        false
      end
    end
    alias_method :"#{attribute}_matches?", :authenticate

    define_method :authenticate_save do |value|
      authenticate(value) && save
    end

    define_method :authenticate_update do |attributes|
      attributes = attributes.dup
      value      = attributes.delete attribute
      authenticate(value, attribute) && update(attributes)
    end

    attr_accessor current_attribute, new_attribute

    define_method :"change_#{attribute}" do
      if valid?(attribute_change)
        current = public_send current_attribute
        if authenticate(current, current_attribute)
          new = public_send new_attribute
          update(attribute => new)
        else
          false
        end
      else
        false
      end
    end

    if validations
      validates column,
                :presence => true
      validates attribute,
                :presence => {
                  :on => :create
                }
      validates current_attribute,
                :presence => {
                  :on => attribute_change
                }
      validates new_attribute,
                :presence => {
                  :on => attribute_change
                }
    end

    if confirmation
      attribute_confirmation     = :"#{attribute}_confirmation"
      new_attribute_confirmation = :"#{new_attribute}_confirmation"
      attr_accessor attribute_confirmation, new_attribute_confirmation

      if validations
        validates attribute,
                  :confirmation => {
                    :on => :create,
                    :if => -> { public_send(attribute).present? }
                  }
        validates attribute_confirmation,
                  :presence => {
                    :on => :create,
                    :if => -> { public_send(attribute).present? }
                  }
        validates new_attribute,
                  :confirmation => {
                    :on => attribute_change,
                    :if => -> { public_send(new_attribute).present? }
                  }
        validates new_attribute_confirmation,
                  :presence => {
                    :on => attribute_change,
                    :if => -> { public_send(new_attribute).present? }
                  }
      end
    end
  end
end

ActiveRecord::Base.send :extend, HasSecureAttribute
