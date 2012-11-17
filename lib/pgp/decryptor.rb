module PGP
  class Decryptor
    include_package "org.bouncycastle.openpgp"

    java_import 'java.io.ByteArrayOutputStream'

    def self.decrypt(encrypted_text, private_key_file)
      bytes = PGP.string_to_bais(encrypted_text)
      dec_s = PGPUtil.get_decoder_stream(bytes)
      pgp_f = PGPObjectFactory.new(dec_s)

      enc_data = pgp_f.next_object
      enc_data = pgp_f.next_object unless PGPEncryptedDataList === enc_data

      data_enumerator = enc_data.get_encrypted_data_objects

      sec_key = nil
      pbe     = nil

      data_enumerator.each do |pubkey_enc_data|
        pbe     = pubkey_enc_data
        key_id  = pubkey_enc_data.get_key_id
        sec_key = PrivateKey.from_file(private_key_file, key_id)

        if sec_key.nil?
          # @todo: Should we notify Airbrake?
          Ace.logger.debug "This may be cause for concern. The data being decrypted has a key_id of '#{key_id}', which can not be found in the private key file '#{CE_Private_Key}'."
        else
          break
        end
      end

      clear = pbe.get_data_stream(sec_key, BC_Provider_Code)

      plain_fact = PGPObjectFactory.new(clear)

      message = plain_fact.next_object

      if(PGPCompressedData === message)
        pgp_fact  = PGPObjectFactory.new(message.get_data_stream)
        message   = pgp_fact.next_object
      end

      baos = ByteArrayOutputStream.new

      if(PGPLiteralData === message)
        unc = message.get_input_stream
        while((ch = unc.read) >= 0)
          baos.write(ch)
        end
      end

      baos.to_string
    end


  end
end
