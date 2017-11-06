class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception
  before_action :auth

  def auth
    redirect_to '/users/sign_in' if current_user.nil?
  end

  def current_user
    @current_user ||= User.find_by_id(session[:user_id])
  end

  def render_ok(data = '')
    render json: {
      status: 'OK',
      data: data
    }
  end

  def render_error(data = '')
    render json: {
      status: 'ERROR',
      data: data
    }
  end
end
