require 'pgp/jars/bcprov-jdk15on-147.jar'
require 'pgp/jars/bcpg-jdk15on-147.jar'
require 'pgp/jruby-pgp.jar'

require 'pgp/decryptor'
require 'pgp/encryptor'
require 'pgp/private_key'
require 'pgp/public_key'

module PGP
  autoload :VERSION, 'pgp/version'

  java_import 'java.security.Security'
  java_import 'org.bouncycastle.jce.provider.BouncyCastleProvider'

  Security.add_provider BouncyCastleProvider.new
end
