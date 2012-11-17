module PGP
  class Encryptor < org.sgonyea.pgp.Encryptor
    include_package "org.bouncycastle.openpgp"

    def add_keys_from_file(filename)
      key_enumerator = keyring_from_file(filename).get_key_rings

      key_enumerator.each do |pk_ring|
        pk_enumerator = pk_ring.get_public_keys

        pk_enumerator.each do |key|
          next unless key.is_encryption_key

          add_public_key key
        end
      end
    end

    protected
    def keyring_from_file(filename)
      file = File.open(filename)
      yafs = PGPUtil.get_decoder_stream(file.to_inputstream)

      PGPPublicKeyRingCollection.new(yafs)
    end

  end
end
