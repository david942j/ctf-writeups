# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# Note that this schema.rb definition is the authoritative source for your
# database schema. If you need to create the application database on another
# system, you should be using db:schema:load, not running all the migrations
# from scratch. The latter is a flawed and unsustainable approach (the more migrations
# you'll amass, the slower it'll run and the greater likelihood for issues).
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema.define(version: 20170930050214) do

  create_table "foots", force: :cascade do |t|
    t.integer "user_id"
    t.integer "post_id"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["post_id", "user_id"], name: "index_foots_on_post_id_and_user_id", unique: true
    t.index ["post_id"], name: "index_foots_on_post_id"
    t.index ["user_id"], name: "index_foots_on_user_id"
  end

  create_table "messages", force: :cascade do |t|
    t.integer "user_id"
    t.integer "from_user_id"
    t.text "content"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["user_id"], name: "index_messages_on_user_id"
  end

  create_table "posts", force: :cascade do |t|
    t.integer "user_id"
    t.text "content"
    t.integer "foots_count", default: 0
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["user_id"], name: "index_posts_on_user_id"
  end

  create_table "users", force: :cascade do |t|
    t.string "account"
    t.string "email"
    t.string "password_digest"
    t.text "oauth"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["account"], name: "index_users_on_account", unique: true
    t.index ["email"], name: "index_users_on_email", unique: true
  end

end
