lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'quayio/scanner/version'

Gem::Specification.new do |spec|
  spec.name          = 'quayio-scanner'
  spec.version       = Quayio::Scanner::VERSION
  spec.authors       = ['Benjamin Meichsner']
  spec.email         = ['benjamin.meichsner@aboutsource.net']

  spec.summary       = 'Scan quay.io for vulnerabilities in '\
                       'running docker containers.'
  spec.homepage      = 'https://github.com/aboutsource/quayio-scanner'
  spec.license       = 'MIT'

  spec.required_ruby_version = '>= 2.3.0'

  spec.files = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.executables   = Dir.glob('bin/**/*.rb').map { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.add_dependency 'docker-api', '~> 1.33'
  spec.add_dependency 'rest-client', '~> 2.1'
  spec.add_dependency 'sensu-plugin', '~> 4.0'
  spec.add_development_dependency 'bundler', '~> 2.1'
  spec.add_development_dependency 'rake', '~> 13.0'
  spec.add_development_dependency 'rspec', '~> 3.7'
  spec.add_development_dependency 'rubocop', '~> 0.49', '<= 0.81'
end
