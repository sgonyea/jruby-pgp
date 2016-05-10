module PGP
  class Signer < org.sgonyea.pgp.Signer
    include_package "org.bouncycastle.openpgp"
    include_package "org.bouncycastle.openpgp.jcajce"

    def add_keys(key_string)
      self.private_keys = keyring_from_string(key_string)
    end

    def add_keys_from_file(filename)
      self.private_keys = keyring_from_file(filename)
    end

    def sign(data)
      signed_data  = sign_data(data.to_java_bytes)
      String.from_java_bytes(signed_data)
    end

    def sign_file(file_path)
      sign File.read(file_path)
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