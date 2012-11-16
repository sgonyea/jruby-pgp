require 'pgp/jars/bcprov-jdk15on-147.jar'
require 'pgp/jars/bcpg-jdk15on-147.jar'
require 'pgp/jruby-pgp.jar'

module PGP
  autoload :VERSION, 'pgp/version'

  java_import 'java.security.Security'
  java_import 'org.bouncycastle.jce.provider.BouncyCastleProvider'

  Security.add_provider BouncyCastleProvider.new
end
