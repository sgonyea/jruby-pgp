require 'spec_helper'

describe PGP::Signer do
  let(:private_key_path)   { Fixtures_Path.join('private_key_with_passphrase.asc').to_s }
  let(:public_key_path)   { Fixtures_Path.join('public_key_with_passphrase.asc').to_s }

  let(:signer) do
    signer = PGP::Signer.new
    signer.passphrase = "testingpgp"
    signer.add_keys_from_file(private_key_path)
    signer
  end

  let(:unsigned_file) { Fixtures_Path.join('signed_file.txt') }
  let(:unsigned_data) { File.read(unsigned_file)}
  let(:signed_file) { Fixtures_Path.join('signed_file.txt.asc') }
  let(:verifier) do
    verifier = PGP::Verifier.new
    verifier.add_keys_from_file(public_key_path)
    verifier
  end

  describe '#sign' do

    it "signs" do
      verifier.verify(signer.sign(unsigned_data)).should == unsigned_data
    end

  end

  describe "encrypting and signing" do
    let(:encryptor) { PGP::Encryptor.new(File.read public_key_path) }
    let(:decryptor) do
      decryptor = PGP::Decryptor.new
      decryptor.passphrase = "testingpgp"
      decryptor.add_keys_from_file(private_key_path)
      decryptor
    end
    it "can decrypt and verify something that has been signed and encrypted" do
      verifier.verify(decryptor.decrypt(encryptor.encrypt(signer.sign("something fabulous")))).should == "something fabulous"
    end
  end

end
