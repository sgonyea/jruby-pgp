module PGP
  class Verifier < org.sgonyea.pgp.Verifier
    include_package "org.bouncycastle.openpgp"

    def add_keys(key_string)
      self.public_keys = keyring_from_string(key_string)
    end

    def add_keys_from_file(filename)
      self.public_keys = keyring_from_file(filename)
    end

    def verify(signed_data)
      input_stream  = PGP.string_to_bais(signed_data)
      verified_data = verify_stream(input_stream)
      String.from_java_bytes(verified_data)
    end

    def decrypt_file(file_path)
      decrypt File.read(file_path)
    end

    def keyring_from_file(filename)
      file = File.open(filename)
      keyring_from_stream(file.to_inputstream)
    end

    def keyring_from_string(key_string)
      keyring_from_stream PGP.string_to_bais(key_string)
    end

    def keyring_from_stream(stream)
      yafs = PGPUtil.get_decoder_stream(stream)
      PGPPublicKeyRingCollection.new(yafs)
    end

  end
end