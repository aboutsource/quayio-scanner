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
              accept: :json
            )
            return JSON.parse(response)
          rescue RestClient::ExceptionWithResponse => e
            raise e if e.http_code != 520 || attempt >= MAX_ATTEMPTS

            sleep(rand(10))
          end
        end
      end
    end
  end
end
