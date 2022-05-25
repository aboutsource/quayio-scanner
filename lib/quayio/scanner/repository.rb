require 'rest-client'
require 'json'

module Quayio
  module Scanner
    Repository = Struct.new(:quayio_token, :org, :repo, :tag) do
      MAX_ATTEMPTS = 5

      def scan
        api_call("/manifest/#{manifest_ref}/security?vulnerabilities=true")
      end

      private

      def manifest_ref
        @manifest_ref ||= fetch_manifest_ref
      end

      def fetch_manifest_ref
        result = api_call("/tag/?specificTag=#{tag}&onlyActiveTags=1")
        result['tags'].first['manifest_digest']
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
