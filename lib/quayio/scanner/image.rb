require 'json'
require 'rest-client'

module Quayio
  module Scanner
    class Image < Struct.new(:name, :quayio_token, :whitelist)
      RELEVANT_SEVERITIES = %w(High Critical)
      MAX_ATTEMPTS = 5

      def vulnerable?
        quayio? && image_exists? && scanned? && high_vulnerabilities_present?
      end

      private

      def quayio?
        name.match(%r{^quay.io\/})
      end

      def image_exists?
        raw_image
      end

      def scanned?
        raw_scan['status'] == 'scanned'
      end

      def high_vulnerabilities_present?
        raw_scan['data']['Layer']['Features'].detect do |f|
          f['Vulnerabilities'] && f['Vulnerabilities'].detect do |v|
            RELEVANT_SEVERITIES.include?(v['Severity']) &&
              !whitelist.include?(v['Name'])
          end
        end
      end

      def repo
        name.split(':').first.gsub(%r{quay.io\/}, '')
      end

      def tag
        name.split(':').last
      end

      def raw_image
        return @raw_image if defined? @raw_image

        (1..MAX_ATTEMPTS).each do |attempt|
          begin
            response = RestClient.get(
              "https://quay.io/api/v1/repository/#{repo}/tag/#{tag}/images",
              authorization: "Bearer #{quayio_token}",
              accept: :json)
          rescue RestClient::ExceptionWithResponse => err
            return nil if err.http_code == 404 # ignore unknown repos
            if err.http_code == 520 and attempt < MAX_ATTEMPTS
              sleep(rand(10))
              next
            end
            raise err
          end
          @raw_image = JSON.parse(response)['images'].first
          return @raw_image
        end
      end

      def raw_scan
        return @raw_scan if defined? @raw_scan

        @raw_scan = begin
          JSON.parse(
            RestClient.get("https://quay.io/api/v1/repository/#{repo}/image/#{raw_image['id']}/security?vulnerabilities=true",
                           authorization: "Bearer #{quayio_token}", accept: :json)
          )
        end
      end
    end
  end
end
