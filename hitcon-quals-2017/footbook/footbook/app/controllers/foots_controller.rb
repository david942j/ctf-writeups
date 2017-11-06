class FootsController < ApplicationController
  def foots
    post_id = params[:post_id].to_i
    post = Post.find_by_id(post_id)
    return render_error if post.nil?
    count = post.foots_count
    unless post.foots.exists?(user_id: current_user.id)
      Foot.create(post_id: post.id, user_id: current_user.id)
      count += 1
    end
    render_ok(count)
  end
end
