require 'spec_helper'

describe PGP::Encryptor do
  let(:private_key_path)  { Fixtures_Path.join('private_key.asc').to_s }
  let(:public_key_path)   { Fixtures_Path.join('public_key.asc').to_s }

  describe '#encrypt' do
    let(:string) { "FooBar" }
    let(:encryptor) { PGP::Encryptor.new }

    context 'When the Public Key is from a file' do
      before {
        encryptor.add_keys_from_file(public_key_path)
      }

      it "it's encrypted string should be decryptable. durr" do
        encrypted_string = encryptor.encrypt(string, "some filename.txt")

        PGP::Decryptor.decrypt(encrypted_string, private_key_path).should == string
      end

      it "should not require that a filename be specified" do
        encrypted_string = encryptor.encrypt(string)

        PGP::Decryptor.decrypt(encrypted_string, private_key_path).should == string
      end
    end # context 'When the Public Key is from a file'

    context 'When the Public Key has been read in to memory' do
      before {
        encryptor.add_keys(File.read public_key_path)
      }

      it "it's encrypted string should be decryptable. durr" do
        encrypted_string = encryptor.encrypt(string, "some filename.txt")

        PGP::Decryptor.decrypt(encrypted_string, private_key_path).should == string
      end

      it "should not require that a filename be specified" do
        encrypted_string = encryptor.encrypt(string)

        PGP::Decryptor.decrypt(encrypted_string, private_key_path).should == string
      end
    end # context 'When the Public Key has been read in to memory'

  end # describe '#encrypt'

end
