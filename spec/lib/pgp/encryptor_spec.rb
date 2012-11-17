require 'spec_helper'

describe PGP::Encryptor do
  let(:private_key_path)  { Fixtures_Path.join('private_key.asc').to_s }
  let(:public_key_path)   { Fixtures_Path.join('public_key.asc').to_s }

  let(:public_key)  { PGP::PublicKey.from_file(public_key_path) }
  # let(:private_key) { PGP::PrivateKey.from_file(public_key_path) }

  describe '#encrypt' do
    let(:string) { "FooBar" }
    let(:encryptor) { PGP::Encryptor.new }

    before {
      encryptor.add_public_key(public_key)
    }

    it "it's encrypted string should be decryptable. durr" do
      encrypted_string = encryptor.encrypt(string.to_java_bytes, "some filename")

      PGP::Decryptor.decrypt(String.from_java_bytes(encrypted_string), private_key_path).should == string
    end
  end

end
