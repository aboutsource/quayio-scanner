require 'rest-client'

module Quayio
  module Scanner
    class Image < Struct.new(:name, :quayio_token)
      RELEVANT_SEVERITIES = %w(High Critical)

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
          f['Vulnerabilities'] &&
            f['Vulnerabilities']
              .detect { |v| RELEVANT_SEVERITIES.include?(v['Severity']) }
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

        @raw_image = begin
          JSON.parse(
            RestClient.get("https://quay.io/api/v1/repository/#{repo}/image",
                           authorization: "Bearer #{quayio_token}", accept: :json)
          )['images'].detect { |i| i['tags'].include?(tag) }
        rescue RestClient::ExceptionWithResponse => err
          return nil if err.http_code == 404 # ignore unknown repos
          raise err
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
