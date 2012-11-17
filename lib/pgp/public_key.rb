module PGP
  # This is more module than class. Eventually it will probably inherit from
  #   the PGPPublicKey class and make using it less ghoulish.
  class PublicKey
    include_package "org.bouncycastle.openpgp"

    def self.from_file(filename)
      keys_from_file(filename).first
    end

    def self.keys_from_file(filename)
      key_enumerator = keyring_from_file(filename).get_key_rings
      encryption_keys = []

      key_enumerator.each do |pk_ring|
        pk_enumerator = pk_ring.get_public_keys

        pk_enumerator.each do |key|
          next unless key.is_encryption_key

          encryption_keys << key
        end
      end

      encryption_keys
    end

    protected
    def self.keyring_from_file(filename)
      file = File.open(filename)
      yafs = PGPUtil.get_decoder_stream(file.to_inputstream)

      PGPPublicKeyRingCollection.new(yafs)
    end

  end
end
