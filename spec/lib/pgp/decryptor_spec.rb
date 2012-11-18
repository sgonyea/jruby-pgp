require 'spec_helper'

describe PGP::Decryptor do
  let(:private_key_path)  { Fixtures_Path.join('private_key.asc').to_s }
  let(:public_key_path)   { Fixtures_Path.join('public_key.asc').to_s }

  let(:decryptor) { PGP::Decryptor.new }

  let(:encrypted_file)    { Fixtures_Path.join('unencrypted_file.txt.asc') }
  let(:encrypted_text)    { File.read(encrypted_file) }
  let(:file_path)         { Fixtures_Path.join('unencrypted_file.txt') }
  let(:unencrypted_text)  { File.read(file_path) }

  describe '#decrypt' do
    before {
      keyring = PGP::PrivateKey.send(:keyring_from_file, private_key_path)
      decryptor.private_keys = keyring
    }

    it "should successfully decrypt an encrypted file" do
      String.from_java_bytes(decryptor.decrypt_stream(PGP.string_to_bais encrypted_text)).should == unencrypted_text
    end
  end
end
