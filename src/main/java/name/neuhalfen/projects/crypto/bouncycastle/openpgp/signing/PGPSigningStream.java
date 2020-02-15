package name.neuhalfen.projects.crypto.bouncycastle.openpgp.signing;


import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPAlgorithmSuite;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.encrypting.PGPEncryptingStream;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.PGPUtilities;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeySelectionStrategy;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeySelectionStrategy.PURPOSE;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Date;
import java.util.Iterator;

import static java.util.Objects.requireNonNull;

/**
 * This class started life as {@link PGPEncryptingStream} and had the encryption stuff hacked out.
 * It's still ugly, but should probably be cleaned up and contributed back to the Bouncy-GPG
 * project.
 */
@SuppressWarnings("PMD.ExcessiveImports")
public final class PGPSigningStream extends OutputStream {

    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory
            .getLogger(PGPSigningStream.class);

    private final KeyringConfig config;
    private final PGPAlgorithmSuite algorithmSuite;
    /**
     * The signature uid.
     */
    private OutputStream encryptionDataStream;
    private PGPSignatureGenerator signatureGenerator;

    @Nullable
    private ArmoredOutputStream armoredOutputStream;
    private OutputStream outerEncryptionStream;
    private BCPGOutputStream compressionStream;
    private PGPLiteralDataGenerator encryptionDataStreamGenerator;
    private PGPCompressedDataGenerator compressionStreamGenerator;

    /*
     * true would mean "This stream is _already_ closed"
     */
    private boolean isClosed = false; // NOPMD: RedundantFieldInitializer

    private PGPSigningStream(final KeyringConfig config, final PGPAlgorithmSuite algorithmSuite) {
        super();
        this.config = config;
        this.algorithmSuite = algorithmSuite;
    }

    /**
     * Return a stream that, when written plaintext into, writes the ciphertext into
     * cipherTextSink.
     *
     * @param config               key configuration
     * @param algorithmSuite       algorithm suite to use.
     * @param signingUid           sign with this uid (optionally)
     * @param cipherTextSink       write the ciphertext in here
     * @param keySelectionStrategy selection strategy
     * @param armor                armor the file (true) or use binary.
     * @return stream where plaintext gets written into
     * @throws IOException              streams, IO, ...
     * @throws PGPException             pgp error
     * @throws NoSuchAlgorithmException algorithmSuite not supported
     * @throws NoSuchProviderException  bouncy castle not registered
     * @see name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.DefaultPGPAlgorithmSuites
     */
    public static OutputStream create(final KeyringConfig config,
                                      final PGPAlgorithmSuite algorithmSuite,
                                      @Nullable final String signingUid,
                                      final OutputStream cipherTextSink,
                                      final KeySelectionStrategy keySelectionStrategy,
                                      final boolean armor)
            throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException {

        requireNonNull(config, "callback must not be null");
        requireNonNull(cipherTextSink, "cipherTextSink must not be null");

        final PGPSigningStream encryptingStream = new PGPSigningStream(config, algorithmSuite);
        encryptingStream.setup(cipherTextSink, signingUid, keySelectionStrategy, armor);
        return encryptingStream;
    }


    /**
     * @param cipherTextSink       Where the ciphertext goes
     * @param signingUid           Sign with this uid. null: do not sign
     * @param keySelectionStrategy key selection strategy (for signatures)
     * @param armor                if OutputStream should be "armored", that means base64 encoded
     * @throws IOException  Signals that an I/O exception has occurred.
     * @throws PGPException the pGP exception
     * @see org.bouncycastle.bcpg.HashAlgorithmTags
     * @see org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
     */
    @SuppressWarnings({"PMD.LawOfDemeter", "PMD.AvoidInstantiatingObjectsInLoops",
            "PMD.CyclomaticComplexity"})
    private void setup(final OutputStream cipherTextSink,
                       final String signingUid,
                       final KeySelectionStrategy keySelectionStrategy,
                       final boolean armor) throws
            IOException, PGPException {

        final OutputStream sink; // NOPMD: PGPSigningStream
        if (armor) {
            this.armoredOutputStream = new ArmoredOutputStream(cipherTextSink);
            sink = this.armoredOutputStream;
        } else {
            sink = cipherTextSink;
        }

        outerEncryptionStream = sink;

        final PGPPublicKey signingPublicKey = keySelectionStrategy
                .selectPublicKey(PURPOSE.FOR_SIGNING, signingUid, config);
        if (signingPublicKey == null) {
            throw new PGPException(
                    "No suitable public key found for signing with uid: '" + signingUid + "'");
        }
        LOGGER.trace("Signing for uid '{}' with key 0x{}.", signingUid,
                Long.toHexString(signingPublicKey.getKeyID()));

        final PGPSecretKey pgpSec = config.getSecretKeyRings()
                .getSecretKey(signingPublicKey.getKeyID());
        if (pgpSec == null) {
            throw new PGPException(
                    "No suitable private key found for signing with uid: '" + signingUid
                            + "' (although found pubkey: " + signingPublicKey.getKeyID() + ")");
        }

        final PGPPrivateKey pgpPrivKey = PGPUtilities.extractPrivateKey(pgpSec,
                config.decryptionSecretKeyPassphraseForSecretKeyId(pgpSec.getKeyID()));
        signatureGenerator = new PGPSignatureGenerator(
                new BcPGPContentSignerBuilder(pgpSec.getPublicKey().getAlgorithm(),
                        algorithmSuite.getHashAlgorithmCode().getAlgorithmId()));

        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

        final Iterator<?> userIDs = pgpSec.getPublicKey().getUserIDs();
        if (userIDs.hasNext()) {
            final PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

            spGen.setSignerUserID(false, (String) userIDs.next());
            signatureGenerator.setHashedSubpackets(spGen.generate());
        }

        compressionStreamGenerator = new PGPCompressedDataGenerator(
                algorithmSuite.getCompressionEncryptionAlgorithmCode().getAlgorithmId());
        compressionStream = new BCPGOutputStream(
                compressionStreamGenerator.open(outerEncryptionStream));

        signatureGenerator.generateOnePassVersion(false).encode(compressionStream);

        encryptionDataStreamGenerator = new PGPLiteralDataGenerator();
        encryptionDataStream = encryptionDataStreamGenerator
                .open(compressionStream, PGPLiteralData.BINARY, "", new Date(), new byte[1 << 16]);
    }

    @Override
    public void write(int data) throws IOException {
        encryptionDataStream.write(data);

        // Sign:
        final byte asByte = (byte) (data & 0xff);
        signatureGenerator.update(asByte);
    }


    @Override
    public void write(@Nonnull byte[] buffer) throws IOException {
        write(buffer, 0, buffer.length);
    }


    @Override
    public void write(@Nonnull byte[] buffer, int off, int len) throws IOException {
        encryptionDataStream.write(buffer, 0, len);

        // Sign:
        signatureGenerator.update(buffer, 0, len);
    }

    @Override
    public void flush() throws IOException {
        encryptionDataStream.flush();
    }

    @Override
    public void close() throws IOException {
        if (!isClosed) {

            encryptionDataStream.flush();
            encryptionDataStream.close();
            encryptionDataStreamGenerator.close();

            try {
                signatureGenerator.generate().encode(compressionStream);  // NOPMD:  Demeter (BC API)
            } catch (PGPException e) {
                throw new IOException(e);
            }

            compressionStreamGenerator.close();

            outerEncryptionStream.flush();
            outerEncryptionStream.close();

            if (armoredOutputStream != null) {
                armoredOutputStream.flush();
                armoredOutputStream.close();
            }
            isClosed = true;
        }
    }
}