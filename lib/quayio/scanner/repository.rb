require 'rest-client'
require 'json'

module Quayio
  module Scanner
    class Repository < Struct.new(:quayio_token, :org, :repo, :tag)
      MAX_ATTEMPTS = 5

      def id
        @id ||= get_id
      end

      def scan
        api_call("/image/#{id}/security?vulnerabilities=true")
      end

      private

      def get_id
        result = api_call("/tag/#{tag}/images")
        (result['images'].first)['id']
      end

      def api_call(uri)
        (1..).each do |attempt|
          begin
            response = RestClient.get(
              "https://quay.io/api/v1/repository/#{org}/#{repo}#{uri}",
              authorization: "Bearer #{quayio_token}",
              accept: :json)
            return JSON.parse(response)
          rescue RestClient::ExceptionWithResponse => err
            raise err if err.http_code != 520 or attempt >= MAX_ATTEMPTS
            sleep(rand(10))
          end
        end
      end
    end
  end
end
