module PGP
  class Encryptor < org.sgonyea.pgp.Encryptor
    include_package "org.bouncycastle.openpgp"

    def add_keys(key_string)
      key_enumerator = keyring_from_string(key_string).get_key_rings
      add_keys_from_enumerator(key_enumerator)
    end

    def add_keys_from_file(filename)
      key_enumerator = keyring_from_file(filename).get_key_rings
      add_keys_from_enumerator(key_enumerator)
    end

    def encrypt(cleartext, filename=nil)
      name  = filename.to_s if filename
      bytes = cleartext.to_java_bytes

      _encrypt(bytes, name)
    end

    # @todo: Create an encryptStream method and pass it the file handle
    def encrypt_file(file_path)
      name  = File.basename(file_path)
      bytes = File.read(file_path).to_java_bytes

      _encrypt(bytes, name)
    end

    protected
    def _encrypt(bytes, name)
      encrypted_bytes   = encrypt_bytes(bytes, name)
      encrypted_string  = String.from_java_bytes(encrypted_bytes)
    end

    def add_keys_from_enumerator(key_enumerator)
      key_enumerator.each do |pk_ring|
        pk_enumerator = pk_ring.get_public_keys

        pk_enumerator.each do |key|
          next unless key.is_encryption_key

          add_public_key key
        end
      end
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
