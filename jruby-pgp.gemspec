# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

require 'pgp/version'

Gem::Specification.new do |gem|
  gem.name          = 'jruby-pgp'
  gem.version       = PGP::VERSION
  gem.authors       = ['Scott Gonyea']
  gem.email         = ['me@sgonyea.com']
  gem.description   = %q{PGP for JRuby}
  gem.summary       = %q{This is a Java+JRuby wrapper around the Bouncy Castle PGP APIs}
  gem.homepage      = 'https://github.com/sgonyea/jruby-pgp'

  gem.files         = `git ls-files`.split($/) + %w[lib/pgp/jruby-pgp.jar]
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ['lib']

  gem.add_development_dependency 'rake'
  gem.add_development_dependency 'rspec'
  gem.add_development_dependency 'rake-compiler'
end
