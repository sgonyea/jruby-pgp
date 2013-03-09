# PGP

This is a Java + JRuby wrapper around the Bouncy Castle PGP APIs. The goal is to write
anything that is memory / object intensive in Java. Use JRuby for everything else.

## Installation

Add this line to your application's Gemfile:

    gem 'jruby-pgp'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install jruby-pgp

## Feature Support:

The feature set is very bare, and restricted to the following operations:

- Encrypt a file to a known list of Public Key(s).

- Decrypt a file using a given set of Private Key(s).

- Public and Private keys may be read in from disk or from memory.

- Verify the signature of a file that you are decrypting. (thanks, @superchris)

- Use password-protected Private Keys. (thanks, @superchris)

- Sign a file from the file system. (thanks, @superchris)

Currently, you **cannot** do the following (These are TODO items):

- Verify any signatures of public / private keys.

- Create new Private Keys / generate public keys from a given Private Key.

- Sign a file that you are encrypting.

- Obtain the name of the file that was encrypted. (Should be an easy feature to add.)

- Obtain the "modificationTime" (timestamp) of the encrypted data / file.

- Verify a public key based on information from a key server.

## Notes

This gem currently features everything I need and nothing I don't. Pull requests are very much welcome;
feature requests will be considered. You may also find examples for certain operations, using the
Bouncy Castle PGP APIs, and link to them in an Issue. That would make their implementation (by me) far
more likely to happen.

The general goal is to provide fast, non-terrible wrappers around the Bouncy Castle PGP APIs. Bare-metal
JRuby code will then plug into those wrappers, to minimize memory bloat. Directly hooking JRuby into the
BC PGP APIs is certainly possible, but they are a pile of rocks. Using these APIs from JRuby can yield
some unwanted bloat, especially when you're resource constrained:

[Example using BC PGP directly from JRuby](https://gist.github.com/1954648)

## Usage

For usage examples, see the below test files:

    Encryption: spec/lib/pgp/encryptor_spec.rb
    Decryption: spec/lib/pgp/decryptor_spec.rb

## Contributors

@superchris

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

## Testing:

Just run:

    $ rake spec

And it will compile the Java extensions prior to running the tests.
