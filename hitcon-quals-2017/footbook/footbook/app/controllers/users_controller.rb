class UsersController < ApplicationController
  skip_before_action :auth, only: %i[sign_in oauth]

  def oauth
    if auth_hash.provider.start_with?('dropbox')
      auth_hash.info = User.info_of_dropbox(auth_hash.credentials.token)
    end
    email = auth_hash.info.email
    email = User.trim_email(email) rescue nil
    return redirect_to root_path if email.nil?
    user = User.find_by_email(email)
    if user.nil?
      user = User.create({
        account: SecureRandom.hex, password: SecureRandom.hex, email: email,
        oauth: {
          auth_hash.provider => auth_hash.info
        }
      })
    else
      if user.oauth[auth_hash.provider].nil?
        user.oauth[auth_hash.provider] = auth_hash.info
        user.save
      end
    end
    session[:user_id] = user.id
    redirect_to root_path
  end

  def sign_in
    return unless params[:account] && params[:password]
    account = params[:account].to_s
    password = params[:password].to_s
    return render_error if account.empty? || account.size > 32 || account.match(/\A[a-zA-Z0-9_\.]+\Z/).nil?
    return render_error if password.empty? || password.size > 60
    user = User.find_by_account(account)
    # sign up
    if user.nil?
      user = User.create({ account: account, password: password, email: User.gen_email(account) })
    else
      return render_error('Wrong password') unless user.authenticate(password)
    end
    session[:user_id] = user.id
    render_ok
  end

  def logout
    session.delete(:user_id)
    redirect_to '/users/sign_in'
  end

  def profile
    user_id = params[:id].to_i
    @user = User.find_by_id(user_id)
    return redirect_to root_path if @user.nil?
    @liked = current_user.foots.pluck(:post_id).to_set
    @posts = @user.posts.common
    render template: 'main/index'
  end

  protected

  def auth_hash
    request.env['omniauth.auth']
  end
end
