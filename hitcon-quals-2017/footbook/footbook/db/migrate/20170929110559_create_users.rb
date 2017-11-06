class CreateUsers < ActiveRecord::Migration[5.1]
  def change
    create_table :users do |t|
      t.string :account
      t.string :email
      t.string :password_digest
      t.text :oauth

      t.timestamps
    end

    add_index :users, :account, unique: true
    add_index :users, :email, unique: true
  end
end
