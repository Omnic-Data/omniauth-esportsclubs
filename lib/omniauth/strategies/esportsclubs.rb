require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Esportsclubs < OmniAuth::Strategies::OAuth2
      DEFAULT_SCOPE = 'Identity'.freeze

      option :name, 'esportsclubs'

      option :client_options,
             site: 'https://esportsclubs.gg/api',
             authorize_url: 'oauth/authorization',
             token_url: 'oauth/token'

      option :authorize_options, %i[scope permissions prompt]

      uid { raw_info['id'] }

      info do
        {
          name: raw_info['username'],
          email: raw_info['email'],
        }
      end

      extra do
        {
          raw_info: raw_info
        }
      end

      def raw_info
        @raw_info ||= access_token.get('users/@me').parsed
      end

      def callback_url
        # Discord does not support query parameters
        options[:redirect_uri] || (full_host + script_name + callback_path)
      end

      def authorize_params
        super.tap do |params|
          options[:authorize_options].each do |option|
            params[option] = request.params[option.to_s] if request.params[option.to_s]
          end

          params[:scope] ||= DEFAULT_SCOPE
        end
      end
    end
  end
end
