module PGP
  # This is more module than class. Eventually it will probably inherit from
  #   the PGPPrivateKey class and make using it less ghoulish.
  class PrivateKey
    include_package "org.bouncycastle.openpgp"

    def self.from_string(string, key_id)
      stream = PGP.string_to_bais(string)
      pgp_sec = keyring_from_stream(stream)
      sec_key = pgp_sec.get_secret_key(key_id)

      sec_key.extract_private_key(nil, BC_Provider_Code) if sec_key
    end

    def self.from_file(filename, key_id)
      pgp_sec = keyring_from_file(filename)
      sec_key = pgp_sec.get_secret_key(key_id)

      sec_key.extract_private_key(nil, BC_Provider_Code) if sec_key
    end

    protected
    def self.keyring_from_file(filename)
      file = File.open(filename)
      keyring_from_stream(file.to_inputstream)
    end

    def self.keyring_from_stream(stream)
      yafs = PGPUtil.get_decoder_stream(stream)
      PGPSecretKeyRingCollection.new(yafs)
    end

  end
end
