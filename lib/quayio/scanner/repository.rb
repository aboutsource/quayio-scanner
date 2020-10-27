require 'rest-client'
require 'json'

module Quayio
  module Scanner
    Repository = Struct.new(:quayio_token, :org, :repo, :tag) do
      MAX_ATTEMPTS = 5

      def id
        @id ||= fetch_id
      end

      def scan
        api_call("/image/#{id}/security?vulnerabilities=true")
      end

      private

      def fetch_id
        result = api_call("/tag/#{tag}/images")
        (result['images'].first)['id']
      end

      def api_call(uri)
        (1..Float::INFINITY).each do |attempt|
          begin
            response = RestClient.get(
              "https://quay.io/api/v1/repository/#{org}/#{repo}#{uri}",
              authorization: "Bearer #{quayio_token}",
              accept: :json,
              open_timeout: 15
            )
            return JSON.parse(response)
          rescue RestClient::Exception => e
            raise e if attempt >= MAX_ATTEMPTS

            # retry later, if we hit cdn rate limiting or on connection errors
            raise e unless e.http_code == 520 || e.http_code.nil?

            sleep(rand(10))
          end
        end
      end
    end
  end
end
