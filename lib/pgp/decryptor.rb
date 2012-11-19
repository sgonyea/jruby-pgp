module PGP
  class Decryptor < org.sgonyea.pgp.Decryptor
    include_package "org.bouncycastle.openpgp"

    def add_keys(key_string)
      self.private_keys = keyring_from_string(key_string)
    end

    def add_keys_from_file(filename)
      self.private_keys = keyring_from_file(filename)
    end

    def decrypt(encrypted_data)
      input_stream    = PGP.string_to_bais(encrypted_data)
      decrypted_data  = decrypt_stream(input_stream)
      String.from_java_bytes(decrypted_data)
    end

    protected
    def keyring_from_file(filename)
      file = File.open(filename)
      keyring_from_stream(file.to_inputstream)
    end

    def keyring_from_string(string)
      input_stream = PGP.string_to_bais(string)
      keyring_from_stream(input_stream)
    end

    def keyring_from_stream(stream)
      yafs = PGPUtil.get_decoder_stream(stream)
      PGPSecretKeyRingCollection.new(yafs)
    end

  end
end
