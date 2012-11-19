/**
 * Much of this code was stolen from this Stack Overflow post:
 *  http://stackoverflow.com/questions/3939447/how-to-encrypt-a-string-stream-with-bouncycastle-pgp-without-starting-with-a-fil
 *
 * In addition to the java versions of this lump of code, that have been floating around on the internet:
 *  https://gist.github.com/1954648
 *
 * Thanks to everyone who has posted on the topic of Bouncy Castle's PGP Library.
**/

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
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;

public class Encryptor {
  private List<PGPPublicKey> _publicKeys;
  private List<BcPublicKeyKeyEncryptionMethodGenerator> _publicKeyEMGs;
  private boolean _integrityCheck;
  private boolean _asciiArmor;
  private char    _format;
  private int     _compression;
  private int     _algorithm;

  private void init() {
    _publicKeys     = new ArrayList<PGPPublicKey>();
    _publicKeyEMGs  = new ArrayList<BcPublicKeyKeyEncryptionMethodGenerator>();
    _integrityCheck = true;
    _asciiArmor     = true;

    useBinaryFormat();
    useZIPCompression();
    useCAST5Algorithm();
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
  **/

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

    clearPublicKeyEMGs();
    addToPublicKeyEMG(publicKeys);
  }

  public List<PGPPublicKey> getPublicKeys() {
    return _publicKeys;
  }

  public void addPublicKey(PGPPublicKey publicKey) {
    _publicKeys.add(publicKey);
    addToPublicKeyEMG(publicKey);
  }

  public void addPublicKeys(List<PGPPublicKey> publicKeys) {
    _publicKeys.addAll(publicKeys);

    addToPublicKeyEMG(publicKeys);
  }

  /* publicKeyEMGs */
  public List<BcPublicKeyKeyEncryptionMethodGenerator> getPublicKeyEMGs() {
    return _publicKeyEMGs;
  }

  public void clearPublicKeyEMGs() {
    _publicKeyEMGs = new ArrayList<BcPublicKeyKeyEncryptionMethodGenerator>();
  }

  public void addToPublicKeyEMG(PGPPublicKey publicKey) {
    _publicKeyEMGs.add(new BcPublicKeyKeyEncryptionMethodGenerator(publicKey));
  }

  public void addToPublicKeyEMG(List<PGPPublicKey> publicKeys) {
    for(PGPPublicKey publicKey : publicKeys) {
      addToPublicKeyEMG(publicKey);
    }
  }

  /* format */
  public char getFormat() {
    return _format;
  }

  public void setFormat(char format) {
    switch(format) {
      case PGPLiteralData.BINARY:
      case PGPLiteralData.TEXT:
      case PGPLiteralData.UTF8:   _format = format; break;
      default:
        throw new IllegalArgumentException("Invalid format. Acceptable formats: 'b', 't', or 'u' (respectively: binary, text, or utf8)");
    }
  }
  public void useBinaryFormat() { setFormat(PGPLiteralData.BINARY); }
  public void useTextFormat()   { setFormat(PGPLiteralData.TEXT);   }
  public void useUTF8Format()   { setFormat(PGPLiteralData.UTF8);   }

  /* compression */
  public int getCompression() {
    return _compression;
  }

  public void setCompression(int compression) {
    _compression = compression;
  }
  public void useNoCompression()    { setCompression(CompressionAlgorithmTags.UNCOMPRESSED); }
  public void useZIPCompression()   { setCompression(CompressionAlgorithmTags.ZIP);   }
  public void useZLIBCompression()  { setCompression(CompressionAlgorithmTags.ZLIB);  }
  public void useBZIP2Compression() { setCompression(CompressionAlgorithmTags.BZIP2); }

  /* algorithm */
  public int getAlgorithm() {
    return _algorithm;
  }

  public void setAlgorithm(int algorithm) {
    _algorithm = algorithm;
  }
  public void useIDEAAlgorithm()      { setAlgorithm(PGPEncryptedData.IDEA);      }
  public void useTripleDESAlgorithm() { setAlgorithm(PGPEncryptedData.TRIPLE_DES);}
  public void useCAST5Algorithm()     { setAlgorithm(PGPEncryptedData.CAST5);     }
  public void useBlowfishAlgorithm()  { setAlgorithm(PGPEncryptedData.BLOWFISH);  }
  public void useSaferAlgorithm()     { setAlgorithm(PGPEncryptedData.SAFER);     }
  public void useDESAlgorithm()       { setAlgorithm(PGPEncryptedData.DES);       }
  public void useAES128Algorithm()    { setAlgorithm(PGPEncryptedData.AES_128);   }
  public void useAES192Algorithm()    { setAlgorithm(PGPEncryptedData.AES_192);   }
  public void useAES256Algorithm()    { setAlgorithm(PGPEncryptedData.AES_256);   }
  public void useTwoFishAlgorithm()   { setAlgorithm(PGPEncryptedData.TWOFISH);   }

  /** End Accessor Methods **/


  /**
   * Encryption Class / Static Methods
  **/

  /**
   * This method preserves the much of the stolen API, so that you can just call the class method should you need to.
  **/
  public static byte[] encryptBytes(byte[] clearData, List<PGPPublicKey> publicKeys, String fileName, boolean withIntegrityCheck, boolean armor)
    throws IOException, PGPException, NoSuchProviderException {
      Encryptor encryptor = new Encryptor(publicKeys);

      return encryptor.encryptBytes(clearData, fileName);
  }


  /**
   * Encryption Instance Methods
  **/
  public byte[] encryptBytes(byte[] clearData, String fileName)
    throws IOException, PGPException, NoSuchProviderException {
      return encryptBytes(clearData, fileName, new Date());
  }

  /**
   * Allows you to override the modificationTime. This method was split off
   *  for mock-free testing of encrypted output.
  **/
  public byte[] encryptBytes(byte[] clearData, String fileName, Date modificationTime)
    throws IOException, PGPException, NoSuchProviderException {
      if (fileName == null)
        fileName = PGPLiteralData.CONSOLE;

      PGPEncryptedDataGenerator   pgpDataGenerator        = newPGPDataGenerator();
      PGPLiteralDataGenerator     dataGenerator           = new PGPLiteralDataGenerator();
      PGPCompressedDataGenerator  compressedDataGenerator = new PGPCompressedDataGenerator(getCompression());

      ByteArrayOutputStream   compressedOutput  = new ByteArrayOutputStream();
      ByteArrayOutputStream   encryptedOutput   = new ByteArrayOutputStream();

      OutputStream  compressedDataStream  = compressedDataGenerator.open(compressedOutput); // open it with the final
      OutputStream  output                = encryptedOutput;
      OutputStream  compressorStream;
      OutputStream  encryptorStream;

      byte[] compressedBytes;

      // Step 1: Compress the data
      compressorStream = dataGenerator.open(
        compressedDataStream, // the compressed output stream
        getFormat(),
        fileName,             // "filename" to store
        clearData.length,     // length of clear data
        modificationTime      // current time
      );
      compressorStream.write(clearData);

      dataGenerator.close();
      compressedDataGenerator.close();

      compressedBytes = compressedOutput.toByteArray();


      // Step 2: ASCII Armor the data if desired
      output = encryptedOutput;
      if (getAsciiArmor())
        output = new ArmoredOutputStream(output);


      // Step 3: Encrypt the data
      encryptorStream = pgpDataGenerator.open(output, compressedBytes.length);
      encryptorStream.write(compressedBytes);
      encryptorStream.close();

      output.close();

      // Return the data as a byte array
      return encryptedOutput.toByteArray();
  }

  public PGPEncryptedDataGenerator newPGPDataGenerator() {
    PGPEncryptedDataGenerator generator;
    BcPGPDataEncryptorBuilder builder;

    builder = new BcPGPDataEncryptorBuilder(getAlgorithm());
    builder.setWithIntegrityPacket(getIntegrityCheck());

    generator = new PGPEncryptedDataGenerator(builder);

    // Add all our public keys to the Data Generator
    for(BcPublicKeyKeyEncryptionMethodGenerator fml : getPublicKeyEMGs()) {
      generator.addMethod(fml);
    }

    return generator;
  }
}
