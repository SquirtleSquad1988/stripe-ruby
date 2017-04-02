module Stripe
  module OAuth
    class StripeOAuthClient < StripeClient
      def self.default_client
        @default_client ||= StripeOAuthClient.new(default_conn)
      end

      def execute_request(method, url,
          api_base: nil, api_key: nil, headers: {}, params: {})
        api_base ||= Stripe.connect_base
        super(method, url, api_base: api_base, api_key: api_key, headers: headers, params: params)
      end

      def handle_api_error(http_resp)
        begin
          resp = StripeResponse.from_faraday_hash(http_resp)
          type = resp.data[:error]
          description = resp.data[:error_description]

          unless type && type.is_a?(String)
            raise StripeError.new("Indeterminate error")
          end

        rescue JSON::ParserError, StripeError
          raise general_api_error(http_resp[:status], http_resp[:body])
        end

        error = OAuthError.new(
          type, description,
          http_status: resp.http_status, http_body: resp.http_body,
          json_body: resp.data, http_headers: resp.http_headers
        )

        error.response = resp
        raise(error)
      end
    end

    module OAuthOperations
      extend APIOperations::Request::ClassMethods

      def self.request(method, url, params={}, opts={})
        opts = Util.normalize_opts(opts)
        opts[:client] ||= StripeOAuthClient.active_client
        opts[:api_base] ||= Stripe.connect_base

        super(method, url, params, opts)
      end
    end

    def self.get_client_id(params={})
      client_id = params[:client_id] || Stripe.client_id
      unless client_id
        raise AuthenticationError.new('No client_id provided. ' \
          'Set your client_id using "Stripe.client_id = <CLIENT-ID>". ' \
          'You can find your client_ids in your Stripe dashboard at ' \
          'https://dashboard.stripe.com/account/applications/settings, ' \
          'after registering your account as a platform. See ' \
          'https://stripe.com/docs/connect/standalone-accounts for details, ' \
          'or email support@stripe.com if you have any questions.')
      end
      client_id
    end

    def self.authorize_url(params={}, opts={})
      base = opts[:connect_base] || Stripe.connect_base

      params[:client_id] = get_client_id(params)
      params[:response_type] ||= 'code'
      query = Util.encode_parameters(params)

      "#{base}/oauth/authorize?#{query}"
    end

    def self.token(params={}, opts={})
      opts = Util.normalize_opts(opts)
      resp, opts = OAuthOperations.request(
        :post, '/oauth/token', params, opts)
      # This is just going to return a generic StripeObject, but that's okay
      Util.convert_to_stripe_object(resp.data, opts)
    end

    def self.deauthorize(params={}, opts={})
      opts = Util.normalize_opts(opts)
      params[:client_id] = get_client_id(params)
      resp, opts = OAuthOperations.request(
        :post, '/oauth/deauthorize', params, opts)
      # This is just going to return a generic StripeObject, but that's okay
      Util.convert_to_stripe_object(resp.data, opts)
    end
  end
end
