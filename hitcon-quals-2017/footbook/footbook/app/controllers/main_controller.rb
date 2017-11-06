class MainController < ApplicationController
  def index
    @show_new = true
    @liked = current_user.foots.pluck(:post_id).to_set
    @posts = Post.common
  end

  # new post
  def post
    content = params[:content].to_s
    return render_error('Invalid') if content.empty? || content.size > 511 || current_user.id <= 1
    Post.create(user_id: current_user.id, content: content)
    redirect_to root_path
  end
end
