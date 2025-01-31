module OmniAuth
  module Strategies
    class Linkedin < OmniAuth::Strategies::OAuth2
      option :name, 'linkedin'

      option :client_options, {
        site: 'https://api.linkedin.com',
        authorize_url: 'https://www.linkedin.com/oauth/v2/authorization',
        token_url: 'https://www.linkedin.com/oauth/v2/accessToken',
        user_info_url: 'https://api.linkedin.com/v2/userinfo'
      }

      option :scope, 'openid profile email'
      option :fields, ['id', 'firstName', 'lastName', 'profilePicture', 'email']

      uid { raw_info['id'] }

      info do
        {
          email: raw_info['email'],
          first_name: raw_info['given_name'],
          last_name: raw_info['family_name'],
          picture_url: raw_info['picture']
        }
      end

      extra do
        { 'raw_info' => raw_info }
      end

      def callback_url
        Rails.logger.debug "[OmniAuth] Generating callback URL"
        url = full_host + script_name + callback_path
        Rails.logger.debug "[OmniAuth] Callback URL: #{url}"
        url
      end

      alias :oauth2_access_token :access_token

      def access_token
        Rails.logger.debug "[OmniAuth] Fetching access token"
        token = ::OAuth2::AccessToken.new(client, oauth2_access_token.token, {
          expires_in: oauth2_access_token.expires_in,
          expires_at: oauth2_access_token.expires_at,
          refresh_token: oauth2_access_token.refresh_token
        })
        Rails.logger.debug "[OmniAuth] Access token fetched: #{token.token}"
        token
      end

      def raw_info
        Rails.logger.debug "[OmniAuth] Fetching raw info"
        @raw_info ||= access_token.get(options.client_options[:user_info_url]).parsed
        Rails.logger.debug "[OmniAuth] Raw info fetched: #{@raw_info}"
        @raw_info
      end

      def setup
        Rails.logger.info "[OmniAuth] Setting up CustomLinkedin strategy"
        options.client_id = '866gzr0nbli6m6'
        options.client_secret = '2eLYr76fzMFgfq5c'
        Rails.logger.debug "[OmniAuth] Client ID: #{options.client_id}, Client Secret: #{options.client_secret}"
        Rails.logger.debug "[OmniAuth] Scopes: #{options.scope}"
        Rails.logger.info "[OmniAuth] CustomLinkedin strategy setup complete"
      end

      private

      def token_params
        Rails.logger.debug "[OmniAuth] Setting token params"
        super.tap do |params|
          params[:redirect_uri] = callback_url
          Rails.logger.debug "[OmniAuth] Token params set: #{params}"
        end
      end
    end
  end
end
