require 'docker'

module Quayio
  module Scanner
    Check = Struct.new(:docker_url, :quayio_token, :whitelist) do
      def run
        Docker.url = docker_url

        if vulnerable_images.empty?
          [:ok, "#{containers.size} Containers are ok"]
        else
          [
            :critical,
            "The images are insecure: #{vulnerable_images.join(', ')}"
          ]
        end
      end

      private

      def containers
        Docker::Container
          .all
          .map { |dc| dc.json['Config']['Image'] }
          .uniq
      end

      def vulnerable_images
        containers
          .map { |container| Image.new(container, quayio_token, whitelist) }
          .select(&:vulnerable?)
          .map(&:name)
      end
    end
  end
end
