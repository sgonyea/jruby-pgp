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
import org.bouncycastle.openpgp.*;

import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

public class Verifier {

  private PGPPublicKeyRingCollection _publicKeys;

  public Verifier() { }
  /**
   * Accessor and Attribute Helper Methods
  **/
  public PGPPublicKeyRingCollection getPublicKeys() {
    return _publicKeys;
  }

  public void setPublicKeys(PGPPublicKeyRingCollection keys) {
    _publicKeys = keys;
  }


  public byte[] verifyStream(InputStream inStream)
    throws Exception
  {
    InputStream in = PGPUtil.getDecoderStream(inStream);

    PGPObjectFactory            pgpFact = new PGPObjectFactory(in);

    PGPCompressedData           c1 = (PGPCompressedData)pgpFact.nextObject();

    pgpFact = new PGPObjectFactory(c1.getDataStream());

    PGPOnePassSignatureList     p1 = (PGPOnePassSignatureList)pgpFact.nextObject();

    PGPOnePassSignature         ops = p1.get(0);

    PGPLiteralData              p2 = (PGPLiteralData)pgpFact.nextObject();

    InputStream                 dIn = p2.getInputStream();
    int                         ch;

    PGPPublicKey                key = _publicKeys.getPublicKey(ops.getKeyID());
    ByteArrayOutputStream       out = new ByteArrayOutputStream();

    ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);

    while ((ch = dIn.read()) >= 0)
    {
      ops.update((byte)ch);
      out.write(ch);
    }

    out.close();

    PGPSignatureList            p3 = (PGPSignatureList)pgpFact.nextObject();

    if (ops.verify(p3.get(0)))
    {
        System.out.println("signature verified.");
    }
    else
    {
        System.out.println("signature verification failed.");
    }
    byte[] returnBytes = out.toByteArray();
    out.close();

    return returnBytes;

  }

}
