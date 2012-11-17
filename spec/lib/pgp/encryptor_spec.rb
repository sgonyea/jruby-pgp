require 'spec_helper'

describe PGP::Encryptor do
  let(:private_key_path)  { Fixtures_Path.join('private_key.asc').to_s }
  let(:public_key_path)   { Fixtures_Path.join('public_key.asc').to_s }

  let(:encryptor) { PGP::Encryptor.new }

  describe '#encrypt' do
    let(:string) { "FooBar" }

    context 'When the Public Key is from a file' do
      before {
        encryptor.add_keys_from_file(public_key_path)
      }

      it "it's encrypted string should be decryptable. durr" do
        encrypted_string = encryptor.encrypt(string, "some filename.txt")

        PGP::RubyDecryptor.decrypt(encrypted_string, private_key_path).should == string
      end

      it "should not require that a filename be specified" do
        encrypted_string = encryptor.encrypt(string)

        PGP::RubyDecryptor.decrypt(encrypted_string, private_key_path).should == string
      end
    end # context 'When the Public Key is from a file'

    context 'When the Public Key has been read in to memory' do
      before {
        encryptor.add_keys(File.read public_key_path)
      }

      it "it's encrypted string should be decryptable. durr" do
        encrypted_string = encryptor.encrypt(string, "some filename.txt")

        PGP::RubyDecryptor.decrypt(encrypted_string, private_key_path).should == string
      end

      it "should not require that a filename be specified" do
        encrypted_string = encryptor.encrypt(string)

        PGP::RubyDecryptor.decrypt(encrypted_string, private_key_path).should == string
      end
    end # context 'When the Public Key has been read in to memory'

  end # describe '#encrypt'

  describe '#encrypt_file' do
    let(:file_path) { Fixtures_Path.join('unencrypted_file.txt') }
    let(:contents) { File.read(file_path) }

    before {
      encryptor.add_keys(File.read public_key_path)
    }

    pending "should have an encryptStream method to avoid memory bloat"

    it "should encrypt a file" do
      encrypted_file = encryptor.encrypt_file(file_path)

      PGP::RubyDecryptor.decrypt(encrypted_file, private_key_path).should == contents
    end
  end # describe '#encrypt_file'

end
