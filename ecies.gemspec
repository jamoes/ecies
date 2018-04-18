require File.expand_path('../lib/ecies/version', __FILE__)

Gem::Specification.new do |s|
  s.name        = 'ecies'
  s.version     = ECIES::VERSION
  s.authors     = ['Stephen McCarthy']
  s.email       = 'sjmccarthy@gmail.com'
  s.summary     = 'Elliptical Curve Integrated Encryption System (ECIES), as specified by SEC 1 - Ver. 2.0'
  s.homepage    = 'https://github.com/jamoes/ecies'
  s.license     = 'MIT'

  s.cert_chain  = ['certs/jamoes.pem']
  s.signing_key = File.expand_path("~/.ssh/gem-private_key.pem") if $0 =~ /gem\z/

  s.files       = `git ls-files`.split("\n")
  s.executables = s.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  s.test_files  = s.files.grep(%r{^(test|spec|features)/})

  s.required_ruby_version = '>= 2.0'

  s.add_development_dependency 'bundler', '~> 1'
  s.add_development_dependency 'rake', '~> 12'
  s.add_development_dependency 'rspec', '~> 3.7'
  s.add_development_dependency 'simplecov', '~> 0'
  s.add_development_dependency 'yard', '~> 0.9.12'
  s.add_development_dependency 'markdown', '~> 1'
  s.add_development_dependency 'redcarpet', '~> 3' unless RUBY_PLATFORM == 'java'
end
