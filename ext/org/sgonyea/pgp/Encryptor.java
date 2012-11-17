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
import java.util.List;
import java.util.ArrayList;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
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

public class Encryptor {
  private List<PGPPublicKey> _publicKeys;
  private boolean _integrityCheck;
  private boolean _asciiArmor;
  private char    _format;
  private int     _compression;

  private void init() {
    _publicKeys     = new ArrayList<PGPPublicKey>();
    _integrityCheck = true;
    _asciiArmor     = true;

    useBinaryFormat();
    useZIPCompression();
  }

  public Encryptor() {
    init();
  }

  public Encryptor(PGPPublicKey publicKey) {
    init();
    addPublicKey(publicKey);
  }

  public Encryptor(List<PGPPublicKey> publicKeys) {
    init();
    addPublicKeys(publicKeys);
  }


  /**
   * Accessor and Attribute Helper Methods
   */

  /* integrityCheck */
  public void setIntegrityCheck(boolean integrityCheck) {
    _integrityCheck = integrityCheck;
  }

  public boolean getIntegrityCheck() {
    return _integrityCheck;
  }

  /* asciiArmor */
  public void setAsciiArmor(boolean asciiArmor) {
    _asciiArmor = asciiArmor;
  }

  public boolean getAsciiArmor() {
    return _asciiArmor;
  }

  /* publicKeys */
  public void setPublicKeys(List<PGPPublicKey> publicKeys) {
    _publicKeys = publicKeys;
  }

  public List<PGPPublicKey> getPublicKeys() {
    return _publicKeys;
  }

  public void addPublicKey(PGPPublicKey publicKey) {
    _publicKeys.add(publicKey);
  }

  public void addPublicKeys(List<PGPPublicKey> publicKeys) {
    _publicKeys.addAll(publicKeys);
  }

  /* format */
  public void setFormat(char format) {
    switch(format) {
      case PGPLiteralData.BINARY:
      case PGPLiteralData.TEXT:
      case PGPLiteralData.UTF8:   _format = format;
                                  break;
      default:
        throw new IllegalArgumentException("Invalid format. Acceptable formats: 'b', 't', or 'u' (respectively: binary, text, or utf8)");
    }
  }

  public char getFormat() {
    return _format;
  }

  public void useBinaryFormat() {
    setFormat(PGPLiteralData.BINARY);
  }

  public void useTextFormat() {
    setFormat(PGPLiteralData.TEXT);
  }

  public void useUTF8Format() {
    setFormat(PGPLiteralData.UTF8);
  }

  /* compression */
  public void setCompression(int compression) {
    _compression = compression;
  }

  public int getCompression() {
    return _compression;
  }

  public void useNoCompression() {
    setCompression(CompressionAlgorithmTags.UNCOMPRESSED);
  }

  public void useZIPCompression() {
    setCompression(CompressionAlgorithmTags.ZIP);
  }

  public void useZLIBCompression() {
    setCompression(CompressionAlgorithmTags.ZLIB);
  }

  public void useBZIP2Compression() {
    setCompression(CompressionAlgorithmTags.BZIP2);
  }


  /**
   * Encryption Class / Static Methods
   */

  /**
   * This method preserves the much of the original API, so that you can just call the class method should you need to.
   */
  public static byte[] encrypt(byte[] clearData, List<PGPPublicKey> publicKeys, String fileName, boolean withIntegrityCheck, boolean armor)
    throws IOException, PGPException, NoSuchProviderException {
      Encryptor encryptor = new Encryptor(publicKeys);

      return encryptor.encrypt(clearData, fileName);
  }


  /**
   * Encryption Instance Methods
   */
  public byte[] encrypt(byte[] clearData, String fileName)
    throws IOException, PGPException, NoSuchProviderException {
      return encrypt(clearData, fileName, new Date());
  }

  /**
   * Allows you to override the modificationTime. This method was split off
   *  for mock-free testing of encrypted output.
   */
  public byte[] encrypt(byte[] clearData, String fileName, Date modificationTime)
    throws IOException, PGPException, NoSuchProviderException {
      if (fileName == null)
        fileName = PGPLiteralData.CONSOLE;

      ByteArrayOutputStream encryptedOutput = new ByteArrayOutputStream();
      OutputStream output = encryptedOutput;

      if (getAsciiArmor())
        output = new ArmoredOutputStream(output);

      ByteArrayOutputStream bOut = new ByteArrayOutputStream();

      PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(getCompression());
      OutputStream cos = comData.open(bOut); // open it with the final
      // destination
      PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();

      // we want to generate compressed data. This might be a user option
      // later,
      // in which case we would pass in bOut.
      OutputStream pOut = lData.open(
              cos,              // the compressed output stream
              getFormat(),
              fileName,         // "filename" to store
              clearData.length, // length of clear data
              modificationTime  // current time
              );
      pOut.write(clearData);

      lData.close();
      comData.close();

      PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(
              PGPEncryptedData.CAST5, getIntegrityCheck(), new SecureRandom(),
              "BC");

      for(PGPPublicKey publicKey : getPublicKeys()) {
        cPk.addMethod(publicKey);
      }

      byte[] bytes = bOut.toByteArray();

      OutputStream cOut = cPk.open(output, bytes.length);

      cOut.write(bytes); // obtain the actual bytes from the compressed stream

      cOut.close();

      output.close();

      return encryptedOutput.toByteArray();
  }
}
