class Post < ApplicationRecord
  belongs_to :user
  has_many :foots

  scope :common, -> { limit(8).order(id: :desc).select(:id, :content, :user_id, :foots_count).includes(:user) }
end
