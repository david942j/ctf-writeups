class User < ApplicationRecord
  ADMIN_EMAIL = 'admin@footbook.meh'.freeze

  has_secure_password validations: false

  serialize :oauth, JSON
  has_many :posts
  has_many :foots
  has_many :messages

  after_initialize :default_values

  private

  def default_values
    self.oauth ||= {}
  end

  class << self
    def gen_email(account)
      account + '@user.footbook.meh'
    end

    def trim_email(email)
      return nil unless email.is_a?(String)
      name, host = email.split('@')
      return nil unless name.is_a?(String) && host.is_a?(String)
      name.gsub!(/\+.*\Z/,'')
      return nil if name.empty? || host.empty?
      name + '@' + host
    end

    def info_of_dropbox(token)
      hash = DropboxApi::Client.new(token).get_current_account.to_hash rescue {}
      OmniAuth::AuthHash::InfoHash.new(hash)
    end
  end
end
