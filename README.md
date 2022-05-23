# Quayio::Scanner

Scan quay.io for vulnerabilties in running docker containers. Implemented as sensu check.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'quayio-scanner'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install quayio-scanner

## USAGE

This plugin attempts to fetch vulnerabilities for all running containers

### Parameters

| Parameter     | Description             |
|---------------|-------------------------|
| -d URL        | Docker URL              |
| -t TOKEN      | Quay.io oauth token     |
| -w WHITELIST  | Vulnerability whitelist |

### Example

    $ check-container-vulnerabilities.rb --docker-url unix:///var/run/docker.sock --quayio-token AccessTokenGoesHere

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/aboutsource/quayio-scanner.

## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).

### json

Copyright 2019 - present [Florian Frank](mailto:flori@ping.de) - The gem [json](https://github.com/flori/json/) is distributed under the [Ruby License](LICENSE/json/LICENSE.txt).

## Security

- [Snyk](https://app.snyk.io/org/about-source/project/6eb2d381-87e7-49c4-a47f-ccad97f33ae3)
