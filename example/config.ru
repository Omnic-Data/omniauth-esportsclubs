require 'bundler/setup'
require 'omniauth'
require 'omniauth-esportsclubs'
require 'sinatra'
require "sinatra/reloader"

configure do
  set :sessions, true
  set :run, false
  set :raise_errors, true
end

use Rack::Session::Cookie, secret: '123456789'

use OmniAuth::Builder do
  provider :discord, ENV['ESPORTSCLUBS_CLIENT_ID'], ENV['ESPORTSCLUBS_CLIENT_ID'], scope: ENV['SCOPE']
end

get '/' do
  content_type 'text/html'
  <<-HTML
    <html>
      <body>
      <form method='post' action='/auth/esportsclubs'>
        <input type="hidden" name="authenticity_token" value='#{request.env["rack.session"]["csrf"]}'>
        <button type='submit'>Login with Esportsclubs</button>
      </form>
      </body>
    </html>
  HTML
end

get '/auth/:provider/callback' do
  content_type 'application/json'
  request.env['omniauth.auth'].to_json
end


run Sinatra::Application
