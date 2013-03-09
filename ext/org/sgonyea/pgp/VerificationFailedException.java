package org.sgonyea.pgp;

public class VerificationFailedException extends Exception {
  public VerificationFailedException(String message) {
    super(message);
  }
}
