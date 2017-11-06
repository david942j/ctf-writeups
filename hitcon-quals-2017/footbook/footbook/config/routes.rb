Rails.application.routes.draw do
  # For details on the DSL available within this file, see http://guides.rubyonrails.org/routing.html
  root to: 'main#index'
  get '/auth/:provider/callback', to: 'users#oauth'
  get '/messages', to: 'messages#show'
  get '/profile/:id', to: 'users#profile'
  get '/users/logout', to: 'users#logout'
  get '/users/sign_in', to: 'users#sign_in'

  post '/foots/:post_id', to: 'foots#foots'
  post '/messages/send', to: 'messages#send_message'
  post '/post', to: 'main#post'
  post '/users/sign_in', to: 'users#sign_in'
end
