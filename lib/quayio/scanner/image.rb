module Quayio
  module Scanner
    class Image
      RELEVANT_SEVERITIES = %w[High Critical].freeze
      QUAY_IO_REPO_NAME =
        %r{quay.io\/(?<org>[\w-]+)\/(?<repo>[\w-]+):(?<tag>[\w.-]+)}.freeze

      attr_reader :name, :whitelist, :repository

      def initialize(name, quayio_token, whitelist)
        @name = name
        @whitelist = whitelist

        @name.match(QUAY_IO_REPO_NAME) do |r|
          org, repo, tag = r.captures
          @repository = Repository.new(quayio_token, org, repo, tag)
        end
      end

      def vulnerable?
        quayio? && scanned? && vulnerabilities_present?
      end

      private

      def quayio?
        # safe guard, do not trust QUAY_IO_REPO_NAME regex match
        name.match?(%r{^quay.io\/})
      end

      def scanned?
        raw_scan['status'] == 'scanned'
      end

      def vulnerabilities_present?
        !raw_scan['data']['Layer']['Features'].detect do |f|
          f['Vulnerabilities']&.detect do |v|
            RELEVANT_SEVERITIES.include?(v['Severity']) &&\
            !whitelist.include?(v['Name'])
          end
        end.nil?
      end

      def raw_scan
        @raw_scan ||= repository.scan
      end
    end
  end
end
