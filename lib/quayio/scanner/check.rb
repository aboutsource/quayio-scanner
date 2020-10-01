require 'docker'

module Quayio
  module Scanner
    class Check < Struct.new(:docker_url, :quayio_token, :whitelist)
      def run
        Docker.url = docker_url
        containers = Docker::Container.all
                                      .map { |dc| dc.json['Config']['Image'] }
                                      .uniq

        vulnerable_images = containers
                            .map { |container| Image.new(container, quayio_token, whitelist) }
                            .select(&:vulnerable?)
                            .map(&:name)

        if vulnerable_images.empty?
          [:ok, "#{containers.size} Containers are ok"]
        else
          [:critical, "The images are insecure: #{vulnerable_images.join(', ')}"]
        end
      end
    end
  end
end
