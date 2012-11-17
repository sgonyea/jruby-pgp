# PGP

This is a Java + JRuby wrapper around the Bouncy Castle PGP APIs.

## Installation

Add this line to your application's Gemfile:

    gem 'jruby-pgp'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install jruby-pgp

## Notes

This gem currently features everything I need and nothing I don't. Pull requests are very much welcome;
feature requests will be considered.

The general goal is to provide fast, non-terrible wrappers around the Bouncy Castle PGP APIs. Bare-metal
JRuby code will then plug into those wrappers, to minimize memory bloat. Directly hooking JRuby into the
BC PGP APIs is certainly possible, but they are a pile of rocks. Using these APIs from JRuby can yield
some unwanted bloat, especially when you're resource constrained:

[Example using BC PGP directly from JRuby](https://gist.github.com/1954648)

## Usage

For usage examples, see the below test files:

    Encryption: spec/lib/pgp/encryptor_spec.rb
    Decryption: spec/lib/pgp/decryptor_spec.rb

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
