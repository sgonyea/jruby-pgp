require 'spec_helper'

describe PGP::Verifier do
  let(:public_key_path)   { Fixtures_Path.join('public_key_with_passphrase.asc').to_s }

  let(:verifier) { PGP::Verifier.new }
  let(:unsigned_file) { Fixtures_Path.join('signed_file.txt') }
  let(:signed_file) { Fixtures_Path.join('signed_file.txt.asc') }

  describe '#verify' do
    context 'When the Public Key is from a file' do
      before do
        verifier.add_keys_from_file(public_key_path)
      end

      it "verifies" do
        verifier.verify(File.read(signed_file)).should == File.read(unsigned_file)
      end
    end

  end

end
