Rails.application.config.middleware.use OmniAuth::Builder do
  provider :twitter, Figaro.env.twitter_api_key, Figaro.env.twitter_api_secret
  provider :github, Figaro.env.github_client_id, Figaro.env.github_client_secret, scope: 'user:email'
  provider :dropbox_oauth2, Figaro.env.dropbox_key, Figaro.env.dropbox_secret
end
