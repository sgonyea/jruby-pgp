require 'spec_helper'
require 'fileutils'

describe PGP::CLI do
  let(:private_key_path)  { Fixtures_Path.join('private_key.asc').to_s }
  let(:public_key_path)   { Fixtures_Path.join('public_key.asc').to_s }

  let(:decrypted_file)  { Fixtures_Path.join('unencrypted_file.txt').to_s }
  let(:encrypted_file)  { Fixtures_Path.join('unencrypted_file.txt.asc').to_s }

  after {
    # These files are created in our current working directory
    FileUtils.rm_rf('unencrypted_file.txt.gpg')
    FileUtils.rm_rf('unencrypted_file.txt')
  }


  describe 'Encrypting' do
    it "should encrypt a given file to the given public key" do
      PGP::CLI::Runner.go!([decrypted_file, "-p", "spec/support/fixtures/public_key.asc"])

      File.exist?('unencrypted_file.txt.gpg').should be_true
    end
  end

  describe 'Decrypting' do
    it "should decrypt a given file to the given private key" do
      PGP::CLI::Runner.go!([encrypted_file, "-P", "spec/support/fixtures/private_key.asc", "-d"])

      File.exist?('unencrypted_file.txt').should be_true
    end
  end

  describe 'Public Keys'

  describe 'Private Keys'

  describe 'Input Files'

  describe 'Output Files'
end
