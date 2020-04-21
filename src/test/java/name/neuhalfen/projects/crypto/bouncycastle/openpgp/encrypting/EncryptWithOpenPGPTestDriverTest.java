package name.neuhalfen.projects.crypto.bouncycastle.openpgp.encrypting;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.DefaultPGPAlgorithmSuites;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.Configs;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.DevNullOutputStream;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.RandomDataInputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.tls.HashAlgorithm;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import static org.hamcrest.Matchers.greaterThan;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.*;


public class EncryptWithOpenPGPTestDriverTest {


  @Before
  public void installBCProvider() {
    BouncyGPG.registerProvider();
  }

  @Test
  public void encryptionAndSigning_anyData_doesNotCloseInputStream()
      throws IOException, SignatureException, NoSuchAlgorithmException, PGPException, NoSuchProviderException {

    final EncryptionConfig config = Configs.buildConfigForEncryptionFromResources();

    EncryptWithOpenPGPTestDriver sut = new EncryptWithOpenPGPTestDriver(
        config,
        DefaultPGPAlgorithmSuites.defaultSuiteForGnuPG());

    InputStream in = mock(InputStream.class);
    when(in.read()).thenReturn(-1);
    when(in.available()).thenReturn(0);
    when(in.read(any(byte[].class))).thenReturn(-1);
    when(in.read(any(byte[].class), any(int.class), any(int.class))).thenReturn(-1);
    when(in.read()).thenReturn(-1);

    sut.encryptAndSign(in, mock(OutputStream.class), config.getEncryptionPublicKeys(), false);

    verify(in, never()).close();
  }


  @Test
  public void encryptionAndSigning_anyData_doesNotCloseOutputStream()
      throws IOException, SignatureException, NoSuchAlgorithmException, PGPException, NoSuchProviderException {

    final EncryptionConfig config = Configs.buildConfigForEncryptionFromResources();

    EncryptWithOpenPGPTestDriver sut = new EncryptWithOpenPGPTestDriver(
        config,
        DefaultPGPAlgorithmSuites.defaultSuiteForGnuPG());

    InputStream in = mock(InputStream.class);
    when(in.read()).thenReturn(-1);
    when(in.available()).thenReturn(0);
    when(in.read(any(byte[].class))).thenReturn(-1);
    when(in.read(any(byte[].class), any(int.class), any(int.class))).thenReturn(-1);
    when(in.read()).thenReturn(-1);

    OutputStream os = mock(OutputStream.class);

    sut.encryptAndSign(in, mock(OutputStream.class), config.getEncryptionPublicKeys(), false);

    verify(os, never()).close();
  }

  @Test(expected = PGPException.class)
  public void encryptionAndSigning_wrongSigningKeyID_throws()
      throws IOException, SignatureException, NoSuchAlgorithmException, PGPException, NoSuchProviderException {

    final EncryptionConfig config = Configs.buildConfigForEncryptionFromResources("unknown", "");

    EncryptWithOpenPGPTestDriver sut = new EncryptWithOpenPGPTestDriver(
        config,
        DefaultPGPAlgorithmSuites.defaultSuiteForGnuPG());

    DevNullOutputStream out = new DevNullOutputStream();

    final int sampleSize = Configs.KB;
    sut.encryptAndSign(someRandomInputData(sampleSize), out, config.getEncryptionPublicKeys(),
        false);
  }

  @Test(expected = PGPException.class)
  public void encryptionAndSigning_wrongSigningKeyPassword_throws()
      throws IOException, SignatureException, NoSuchAlgorithmException, PGPException, NoSuchProviderException {

    final EncryptionConfig config = Configs
        .buildConfigForEncryptionFromResources("sender@example.com", "wrong");

    EncryptWithOpenPGPTestDriver sut = new EncryptWithOpenPGPTestDriver(
        config,
        DefaultPGPAlgorithmSuites.defaultSuiteForGnuPG());

    DevNullOutputStream out = new DevNullOutputStream();

    final int sampleSize = Configs.KB;
    sut.encryptAndSign(someRandomInputData(sampleSize), out, config.getEncryptionPublicKeys(),
        false);
  }

  @Test(expected = PGPException.class)
  public void encryption_toSignOnlyKey_throws()
      throws IOException, SignatureException, NoSuchAlgorithmException, PGPException, NoSuchProviderException {

    final KeyringConfig keyringConfig = Configs
        .keyringConfigFromResourceForSender(KeyringConfigCallbacks.withPassword("sign"));

    //  sender.signonly@example.com is a "sign only" DSA key.
    // trying to encrypt to that key should not be possible
    EncryptionConfig encryptAndSignConfig = new EncryptionConfig(
        "sender@example.com",
        "sender.signonly@example.com",
        HashAlgorithm.sha1,
        keyringConfig);
    EncryptWithOpenPGPTestDriver sut = new EncryptWithOpenPGPTestDriver(encryptAndSignConfig,
        DefaultPGPAlgorithmSuites.defaultSuiteForGnuPG());

    final int sampleSize = Configs.KB;
    sut.encryptAndSign(someRandomInputData(sampleSize), new DevNullOutputStream(),
        encryptAndSignConfig.getEncryptionPublicKeysNoValidation(), false);
  }


  @Test
  public void encryptionAndSigning_smallAmountsOfData_doesNotCrash()
      throws IOException, SignatureException, NoSuchAlgorithmException, PGPException, NoSuchProviderException {

    final EncryptionConfig config = Configs.buildConfigForEncryptionFromResources();
    EncryptWithOpenPGPTestDriver sut = new EncryptWithOpenPGPTestDriver(
        config,
        DefaultPGPAlgorithmSuites.defaultSuiteForGnuPG());

    DevNullOutputStream out = new DevNullOutputStream();

    final int sampleSize = 1 * Configs.KB;
    sut.encryptAndSign(someRandomInputData(sampleSize), out, config.getEncryptionPublicKeys(),
        false);

    assertThat("A compression>50% is fishy!", out.getBytesWritten(), greaterThan(sampleSize / 2));
  }


  @Test
  public void encryptionRSAAndSigningWithDSA_smallAmountsOfData_doesNotCrash()
      throws IOException, SignatureException, NoSuchAlgorithmException, PGPException, NoSuchProviderException {
    final KeyringConfig keyringConfig = Configs
        .keyringConfigFromResourceForSender(KeyringConfigCallbacks.withPassword("sign"));

    //  sender.signonly@example.com is a "sign only" DSA key.
    // trying to encrypt to that key should not be possible
    EncryptionConfig encryptAndSignConfig = new EncryptionConfig(
        "sender.signonly@example.com",
        "sender@example.com",
        HashAlgorithm.sha1,
        keyringConfig);
    EncryptWithOpenPGPTestDriver sut = new EncryptWithOpenPGPTestDriver(encryptAndSignConfig,
        DefaultPGPAlgorithmSuites.defaultSuiteForGnuPG());

    final int sampleSize = Configs.KB;
    sut.encryptAndSign(someRandomInputData(sampleSize), new DevNullOutputStream(),
        encryptAndSignConfig.getEncryptionPublicKeys(), false);
  }

  /**
   * This is really a "does not crash for moderate amounts of data" test.
   */
  @Test
  @Ignore("this test is  slow (~2sec)")
  public void encryptionAndSigning_10MB_isFast()
      throws IOException, SignatureException, NoSuchAlgorithmException, PGPException, NoSuchProviderException {
    final EncryptionConfig config = Configs.buildConfigForEncryptionFromResources();
    EncryptWithOpenPGPTestDriver sut = new EncryptWithOpenPGPTestDriver(
        config,
        DefaultPGPAlgorithmSuites.defaultSuiteForGnuPG());

    DevNullOutputStream out = new DevNullOutputStream();

    final int sampleSize = 10 * Configs.MB;
    sut.encryptAndSign(someRandomInputData(sampleSize), out, config.getEncryptionPublicKeys(),
        false);

    assertThat("A compression>50% is fishy!", out.getBytesWritten(), greaterThan(sampleSize / 2));
  }


  @Test
  @Ignore("this test is very slow (~2min)")
  public void encryptionAndSigning_1GB_doesNotCrash()
      throws IOException, SignatureException, NoSuchAlgorithmException, PGPException, NoSuchProviderException {
    final EncryptionConfig config = Configs.buildConfigForEncryptionFromResources();
    EncryptWithOpenPGPTestDriver sut = new EncryptWithOpenPGPTestDriver(
        config,
        DefaultPGPAlgorithmSuites.defaultSuiteForGnuPG());

    DevNullOutputStream out = new DevNullOutputStream();

    final int sampleSize = 1 * Configs.GB;
    sut.encryptAndSign(someRandomInputData(sampleSize), out, config.getEncryptionPublicKeys(),
        false);

    assertThat("A compression>50% is fishy!", out.getBytesWritten(), greaterThan(sampleSize / 2));
  }


  private InputStream someRandomInputData(int len) {
    return new RandomDataInputStream(len);
  }

}
