require 'rest-client'
require 'json'

module Quayio
  module Scanner
    class Repository < Struct.new(:quayio_token, :repo)
      MAX_ATTEMPTS = 5

      def id(tag)
        result = api_call("/tag/#{tag}/images")
        return (result['images'].first)['id']
      end

      def scan(id)
        return api_call("/image/#{id}/security?vulnerabilities=true")
      end

      private

      def api_call(uri)
        (1..Float::INFINITY).each do |attempt|
          begin
            response = RestClient.get(
              "https://quay.io/api/v1/repository/#{repo}#{uri}",
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
