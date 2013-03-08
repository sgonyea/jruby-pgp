require 'spec_helper'

describe PGP::Signer do
  let(:private_key_path)   { Fixtures_Path.join('private_key_with_passphrase.asc').to_s }
  let(:public_key_path)   { Fixtures_Path.join('public_key_with_passphrase.asc').to_s }

  let(:signer) { PGP::Signer.new }
  let(:unsigned_file) { Fixtures_Path.join('signed_file.txt') }
  let(:unsigned_data) { File.read(unsigned_file)}
  let(:signed_file) { Fixtures_Path.join('signed_file.txt.asc') }
  let(:verifier) do
    verifier = PGP::Verifier.new
    verifier.add_keys_from_file(public_key_path)
    verifier
  end

  describe '#sign' do
    context 'When the Public Key is from a file' do

      before do
        signer.passphrase = "testingpgp"
        signer.add_keys_from_file(private_key_path)
      end

      it "signs" do
        verifier.verify(signer.sign(unsigned_data)).should == unsigned_data
      end
    end

  end

end
