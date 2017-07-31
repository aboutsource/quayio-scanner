#! /usr/bin/env ruby
#
#   check-container-vulnerabilities
#
# DESCRIPTION:
#
#   This plugin attempts to fetch vulnerabilties for all running containers
#
# OUTPUT:
#   plain text
#
# PLATFORMS:
#   Linux
#
# DEPENDENCIES:
#   gem: sensu-plugin
#   gem: docker-api
#   gem: rest-client
#
# USAGE:
#   ./check-container-vulnerabilities.rb -d <docker-url> -t <quay-io-oauth-token>
#

require 'sensu-plugin/check/cli'
require 'quayio/scanner'

class CheckContainerVulnerabilities < Sensu::Plugin::Check::CLI
  option :docker_url,
         description: 'Docker URL',
         short: '-d URL',
         long: '--docker-url URL',
         default: 'unix:///var/run/docker.sock'

  option :quayio_token,
         description: 'Quay.io oauth token',
         short: '-t TOKEN',
         long: '--quayio-token TOKEN'

  def run
    result = Quayio::Scanner::Check.new(config[:docker_url],
                                        config[:quayio_token]).run

    if result[0] == :ok
      ok result[1]
    else
      critical result[1]
    end
  end
end
