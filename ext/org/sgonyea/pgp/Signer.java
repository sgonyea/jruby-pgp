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

import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

public class Signer {

  private PGPSecretKeyRingCollection _privateKeys;

  private String passphrase;

  public Signer() { }
  public Signer(PGPSecretKeyRingCollection privateKeys) {
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

  public void setPassphrase(String passphrase) {
    this.passphrase = passphrase;
  }

  private PGPSecretKey findSecretKey()
    throws PGPException, NoSuchProviderException {
    Iterator keyRingIter = _privateKeys.getKeyRings();
    while (keyRingIter.hasNext())
    {
        PGPSecretKeyRing keyRing = (PGPSecretKeyRing)keyRingIter.next();

        Iterator keyIter = keyRing.getSecretKeys();
        while (keyIter.hasNext())
        {
            PGPSecretKey key = (PGPSecretKey)keyIter.next();

            if (key.isSigningKey())
            {
                return key;
            }
        }
    }

    throw new IllegalArgumentException("Can't find signing key in key ring.");
  }


  public byte[] signStream(InputStream inStream)
    throws Exception {
      String fileName = "something.txt";
      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      ArmoredOutputStream out = new ArmoredOutputStream(bos);

      PGPSecretKey                pgpSec = findSecretKey();
      PGPPrivateKey               pgpPrivKey = pgpSec.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passphrase.toCharArray()));
      PGPSignatureGenerator       sGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpSec.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));

      sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

      Iterator    it = pgpSec.getPublicKey().getUserIDs();
      if (it.hasNext())
      {
          PGPSignatureSubpacketGenerator  spGen = new PGPSignatureSubpacketGenerator();

          spGen.setSignerUserID(false, (String)it.next());
          sGen.setHashedSubpackets(spGen.generate());
      }

      PGPCompressedDataGenerator  cGen = new PGPCompressedDataGenerator(
                                                              PGPCompressedData.ZLIB);

      BCPGOutputStream            bOut = new BCPGOutputStream(cGen.open(out));

      sGen.generateOnePassVersion(false).encode(bOut);

      File                        file = new File(fileName);
      PGPLiteralDataGenerator     lGen = new PGPLiteralDataGenerator();
      OutputStream                lOut = lGen.open(bOut, PGPLiteralData.BINARY, file);
      int                         ch;

      while ((ch = inStream.read()) >= 0)
      {
          lOut.write(ch);
          sGen.update((byte)ch);
      }

      lGen.close();

      sGen.generate().encode(bOut);

      cGen.close();

      System.out.println(bos.toString());
      return bos.toByteArray();
  }


}
