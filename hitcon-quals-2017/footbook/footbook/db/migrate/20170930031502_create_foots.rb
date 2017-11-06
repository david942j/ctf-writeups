class CreateFoots < ActiveRecord::Migration[5.1]
  def change
    create_table :foots do |t|
      t.integer :user_id
      t.integer :post_id

      t.timestamps
    end

    add_index :foots, :post_id
    add_index :foots, :user_id
    add_index :foots, [:post_id, :user_id], unique: true
  end
end
