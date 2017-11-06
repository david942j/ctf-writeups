class CreatePosts < ActiveRecord::Migration[5.1]
  def change
    create_table :posts do |t|
      t.integer :user_id
      t.text :content
      t.integer :foots_count, default: 0

      t.timestamps
    end

    add_index :posts, :user_id
  end
end
