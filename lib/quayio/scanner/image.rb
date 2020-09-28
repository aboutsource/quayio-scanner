require 'quayio/scanner/repository'

module Quayio
  module Scanner
    class Image
      RELEVANT_SEVERITIES = %w(High Critical)

      def initialize(name, quayio_token, whitelist)
        @name = name
        @whitelist = whitelist

        repo = name.split(':').first.gsub(%r{quay.io\/}, '')
        @repository = Repository.new(quayio_token, repo)
      end

      def vulnerable?
        quayio? && image_exists? && scanned? && vulnerabilities_present?
      end

      private

      def quayio?
        @name.match(%r{^quay.io\/})
      end

      def image_exists?
        raw_id
      end

      def scanned?
        raw_scan['status'] == 'scanned'
      end

      def vulnerabilities_present?
        raw_scan['data']['Layer']['Features'].detect do |f|
          f['Vulnerabilities'] && f['Vulnerabilities'].detect do |v|
            RELEVANT_SEVERITIES.include?(v['Severity']) &&
              !@whitelist.include?(v['Name'])
          end
        end
      end

      def tag
        @name.split(':').last
      end

      def raw_id
        return @raw_id if defined? @raw_id

        @raw_id = @repository.id(tag)
        return @raw_id
      end

      def raw_scan
        return @raw_scan if defined? @raw_scan

        @raw_scan = @repository.scan(raw_id)
        return @raw_scan
      end
    end
  end
end
