/**
 * Much of this code was stolen from this Stack Overflow post:
 *  http://stackoverflow.com/questions/3939447/how-to-encrypt-a-string-stream-with-bouncycastle-pgp-without-starting-with-a-fil
 *
 * In addition to the java versions of this lump of code, that have been floating around on the internet:
 *  https://gist.github.com/1954648
 *
 * Thanks to everyone who has posted on the topic of Bouncy Castle's PGP Library.
 */

package org.sgonyea.pgp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;

public class Decryptor {

  private PGPSecretKeyRingCollection _privateKeys;

  public Decryptor() { }
  public Decryptor(PGPSecretKeyRingCollection privateKeys) {
    setPrivateKeys(privateKeys);
  }

  /**
   * Accessor and Attribute Helper Methods
  **/
  public PGPSecretKeyRingCollection getPrivateKeys() {
    return _privateKeys;
  }

  public void setPrivateKeys(PGPSecretKeyRingCollection privateKeys) {
    _privateKeys = privateKeys;
  }

  public PGPPrivateKey findPrivateKey(long keyID)
    throws PGPException, NoSuchProviderException {
      PGPSecretKey pgpSecKey = getPrivateKeys().getSecretKey(keyID);

      if (pgpSecKey == null)
        return null;

      // null = the password. We won't need this for now.
      return pgpSecKey.extractPrivateKey(null, "BC");
  }

  /** End Accessor Methods **/

  /**
   * Decryption Instance Methods
  **/

  public byte[] decryptBytes(byte[] encryptedBytes)
    throws IOException, PGPException, NoSuchProviderException {
      InputStream stream = new ByteArrayInputStream(encryptedBytes);
      return decryptStream(stream);
  }

  public byte[] decryptStream(InputStream encryptedStream)
    throws IOException, PGPException, NoSuchProviderException {

      InputStream decoderStream = PGPUtil.getDecoderStream(encryptedStream);

      PGPObjectFactory pgpF = new PGPObjectFactory(decoderStream);
      PGPEncryptedDataList encryptedData = null;
      Object encryptedObj = pgpF.nextObject();
      Iterator encryptedDataIterator;
      PGPPublicKeyEncryptedData publicKeyData = null;
      PGPPrivateKey privateKey = null;

      // the first object might be a PGP marker packet.
      if (encryptedObj instanceof PGPEncryptedDataList)
        encryptedData = (PGPEncryptedDataList) encryptedObj;
      else
        encryptedData = (PGPEncryptedDataList) pgpF.nextObject();

      encryptedDataIterator = encryptedData.getEncryptedDataObjects();

      while (privateKey == null && encryptedDataIterator.hasNext()) {
        publicKeyData = (PGPPublicKeyEncryptedData) encryptedDataIterator.next();

        privateKey = findPrivateKey(publicKeyData.getKeyID());
      }

      if (privateKey == null)
        throw new IllegalArgumentException("secret key for message not found.");

      InputStream clear = publicKeyData.getDataStream(privateKey, "BC");

      PGPObjectFactory pgpFact = new PGPObjectFactory(clear);

      PGPCompressedData cData = (PGPCompressedData) pgpFact.nextObject();

      pgpFact = new PGPObjectFactory(cData.getDataStream());

      PGPLiteralData ld = (PGPLiteralData) pgpFact.nextObject();

      InputStream unc = ld.getInputStream();

      ByteArrayOutputStream out = new ByteArrayOutputStream();
      int ch;

      while ((ch = unc.read()) >= 0) {
          out.write(ch);

      }

      byte[] returnBytes = out.toByteArray();
      out.close();
      return returnBytes;
  }

}
