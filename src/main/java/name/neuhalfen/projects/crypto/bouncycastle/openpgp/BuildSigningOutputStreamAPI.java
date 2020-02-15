package name.neuhalfen.projects.crypto.bouncycastle.openpgp;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.DefaultPGPAlgorithmSuites;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPAlgorithmSuite;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.ByEMailKeySelectionStrategy;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeySelectionStrategy;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeySelectionStrategy.PURPOSE;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallback;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.Rfc4880KeySelectionStrategy;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.InMemoryKeyring;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.signing.PGPSigningStream;
import name.neuhalfen.projects.crypto.internal.Preconditions;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

import javax.annotation.Nullable;

import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import static java.util.Objects.requireNonNull;

/**
 * This is my attempt to add the ability to produce a digital signature to the Bouncy-GPG package.
 * It started life as {@link BuildEncryptionOutputStreamAPI} and then I started removing encryption
 * stuff. I haven't gone through this that carefully, but have done some quick tests and it does
 * produce GPG-compatible digital signatures.
 * <p>
 * This should probably be cleaned up and presented as a pull request to the Bouncy-GPG project as
 * there is an open issue regarding digital signatures.
 */
@SuppressWarnings({"PMD.GodClass", "PMD.AtLeastOneConstructor",
        "PMD.AccessorMethodGeneration", "PMD.LawOfDemeter", "Checkstyle.AbbreviationAsWordInName"})
public final class BuildSigningOutputStreamAPI {

    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory
            .getLogger(BuildSigningOutputStreamAPI.class);

    @SuppressWarnings({"PMD.ImmutableField"})
    private WithKeySelectionStrategy keySelectionStrategyBuilder;

    /*
     * lazily populated by getKeySelectionStrategy()
     */
    private KeySelectionStrategy keySelectionStrategy;

    private OutputStream sinkForSignedData;
    private KeyringConfig signingConfig;
    private PGPAlgorithmSuite algorithmSuite;

    private String signWith;
    private boolean armorOutput;

    /**
     * <p>Use the passed keyring config for the crypto operations. The KeyringConfig wraps the
     * public- and private keyrings. </p><p> Generally the best KeyringConfig variant to use is the
     * {@link InMemoryKeyring} which can be created by calling {@link KeyringConfigs#forGpgExportedKeys(KeyringConfigCallback)}.
     * </p>
     *
     * @param signingConfig the keyring config.
     * @return the next step in the builder
     * @throws IOException  bouncy castle uses IO
     * @throws PGPException errors in the config
     * @see KeyringConfigs
     * @see InMemoryKeyring
     */
    @SuppressWarnings("PMD.AccessorClassGeneration")
    public WithKeySelectionStrategy withConfig(final KeyringConfig signingConfig)
            throws IOException, PGPException {
        requireNonNull(signingConfig, "signingConfig must not be null");
        requireNonNull(signingConfig.getKeyFingerPrintCalculator(),
                "signingConfig.getKeyFingerPrintCalculator() must not be null");
        requireNonNull(signingConfig.getPublicKeyRings(),
                "signingConfig.getPublicKeyRings() must not be null");

        this.signingConfig = signingConfig;
        return new WithKeySelectionStrategy();
    }

    private KeySelectionStrategy getKeySelectionStrategy() {
        if (this.keySelectionStrategy == null) {
            this.keySelectionStrategy = this.keySelectionStrategyBuilder
                    .buildKeySelectionStrategy();
        }
        return this.keySelectionStrategy;
    }

    public interface Build {
        OutputStream andWriteTo(OutputStream sinkForSignedData)
                throws PGPException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException, IOException;
    }

    public interface WithAlgorithmSuite {

        /**
         * The (older) default suite for gpg.: <dl> <dt>hash</dt><dd>SHA-1</dd>
         * <dt>chipher</dt><dd>CAST 5</dd>
         * <dt>compression</dt><dd>ZLIB</dd> </dl> <p> <p><b>Only recommended if {@link
         * #withStrongAlgorithms()} cannot be used.</b></p>
         *
         * @return next step
         */
        SignWith withDefaultAlgorithms();

        /**
         * Use a strong suite of algorithms that is understood by gpg. It is a sensible suite with
         * strong algorithms:
         * <dl> <dt>hash</dt><dd>SHA-256</dd> <dt>chipher</dt><dd>AES-128</dd>
         * <dt>compression</dt><dd>ZLIB</dd> </dl>
         * <p>This is <b>recommended</b> over {@link #withDefaultAlgorithms()}.</p>
         *
         * @return next step
         */
        SignWith withStrongAlgorithms();

        /**
         * Use the default algorithm suite for <a href="https://xmpp.org/extensions/xep-0373.html">XEP-0373</a>,
         * OpenPGP for XMPP. It is a sensible suite with strong algorithms but without
         * compression.:
         * <dl>
         * <dt>hash</dt><dd>SHA-256</dd> <dt>chipher</dt><dd>AES-128</dd>
         * <dt>compression</dt><dd>uncompressed</dd>
         * </dl>
         *
         * @return next step
         */
        SignWith withOxAlgorithms();

        /**
         * Use a custom algorithm set.
         *
         * @param algorithmSuite algorithm suite to use
         * @return next step
         * @see DefaultPGPAlgorithmSuites
         */
        SignWith withAlgorithms(PGPAlgorithmSuite algorithmSuite);

        interface SignWith {

            /**
             * Sign the message with the following user id. The key used will be sought by the key
             * selection strategy.
             *
             * @param userId sign with this userid
             * @return next step
             * @throws IOException  IO is dangerous
             * @throws PGPException Something with GPG went wrong (e.g. key not found)
             */
            Armor andSignWith(String userId) throws IOException, PGPException;

            interface Armor {

                /**
                 * Write as binary output.
                 *
                 * @return next step
                 */
                Build binaryOutput();

                /**
                 * Ascii armor the output, e.g. for usage in text protocols.
                 *
                 * @return next step
                 */
                Build armorAsciiOutput();
            }

        }
    }

    /**
     * Combined step for key- and algorithm selection.
     */
    public final class WithKeySelectionStrategy extends WithAlgorithmSuiteImpl {

        private static final boolean SELECT_UID_BY_E_MAIL_ONLY_DEFAULT = true;

        @Nullable
        private Long dateOfTimestampVerification;

        @Nullable
        @SuppressWarnings({"PMD.LinguisticNaming"})
        private Boolean selectUidByEMailOnly;

        @Nullable
        private KeySelectionStrategy keySelectionStrategy;

        private WithKeySelectionStrategy() {
            super();
            BuildSigningOutputStreamAPI.this.keySelectionStrategyBuilder = this;
        }

        /**
         * <p> Normally keys are only searched by e-mail (between &lt; and &gt;). Calling
         * selectUidByAnyUidPart() will search everywhere. </p><p> E.g. given the uid 'Juliet
         * Capulet &lt;juliet@example.org&gt;' a search normally would look for the e-mail
         * 'juliet@example.org'. E.g. searching for 'juliet' would be found, searching for 'Capulet'
         * would not be found. </p> <p> After calling selectUidByAnyUidPart() the key will also be
         * found by searching for 'Capulet'
         * </p>
         *
         * @return next step
         */
        public WithKeySelectionStrategy selectUidByAnyUidPart() {
            Preconditions.checkState(keySelectionStrategy == null,
                    "selectUidByAnyUidPart/setReferenceDateForKeyValidityTo cannot be" +
                            " used together with 'withKeySelectionStrategy' ");

            selectUidByEMailOnly = false;
            return this;
        }

        /**
         * In order to determine key validity a reference point in time for "now" is needed. The
         * default value is "Instant.now()". If this needs to be overridden, pass the value here. To
         * effectively disable time based key verification pass Instant.MAX (NOT recommended)
         * <p>
         * This is not possible in combination with #withKeySelectionStrategy.
         *
         * @param dateOfTimestampVerification reference point in time
         * @return next step in build
         */
        @SuppressWarnings("PMD.LinguisticNaming")
        public WithAlgorithmSuite setReferenceDateForKeyValidityTo(
                final Long dateOfTimestampVerification) {

            Preconditions.checkState(keySelectionStrategy == null,
                    "selectUidByAnyUidPart/setReferenceDateForKeyValidityTo cannot be"
                            + " used together with 'withKeySelectionStrategy' ");

            requireNonNull(dateOfTimestampVerification,
                    "dateOfTimestampVerification must not be null");

            this.dateOfTimestampVerification = dateOfTimestampVerification;
            LOGGER.trace("WithKeySelectionStrategy: setReferenceDateForKeyValidityTo {}",
                    dateOfTimestampVerification);
            return this;
        }

        /**
         * The default strategy to search for keys is to *just* search for the email address (the
         * part between &lt; and &gt;).
         * <p>
         * Set this flag to search for any part in the user id.
         *
         * @param strategy instance to use
         * @return next build step
         */
        public WithAlgorithmSuite withKeySelectionStrategy(final KeySelectionStrategy strategy) {
            requireNonNull(strategy, "strategy must not be null");

            Preconditions.checkState(
                    selectUidByEMailOnly == null && dateOfTimestampVerification == null,
                    "selectUidByAnyUidPart/setReferenceDateForKeyValidityTo cannot be used together"
                            + " with 'withKeySelectionStrategy' ");

            this.keySelectionStrategy = strategy;
            LOGGER.trace("WithKeySelectionStrategy: override strategy to {}",
                    strategy.getClass().toGenericString());
            return this;
        }


        // Duplicate of BuildDecryptionInputStreamAPI
        @SuppressWarnings({"PMD.OnlyOneReturn"})
        private KeySelectionStrategy buildKeySelectionStrategy() {
            final boolean hasExistingStrategy = this.keySelectionStrategy != null;
            if (hasExistingStrategy) {
                return this.keySelectionStrategy;
            } else {
                if (this.selectUidByEMailOnly == null) {
                    this.selectUidByEMailOnly = SELECT_UID_BY_E_MAIL_ONLY_DEFAULT;
                }
                if (this.dateOfTimestampVerification == null) {
                    this.dateOfTimestampVerification = System.currentTimeMillis();
                }

                if (this.selectUidByEMailOnly) {
                    return new ByEMailKeySelectionStrategy(this.dateOfTimestampVerification);
                } else {
                    return new Rfc4880KeySelectionStrategy(this.dateOfTimestampVerification);
                }
            }
        }
    }

    private class WithAlgorithmSuiteImpl implements WithAlgorithmSuite {

        @Override
        public SignWith withDefaultAlgorithms() {
            BuildSigningOutputStreamAPI.this.algorithmSuite = DefaultPGPAlgorithmSuites
                    .defaultSuiteForGnuPG();
            LOGGER
                    .trace("use algorithms {}",
                            BuildSigningOutputStreamAPI.this.algorithmSuite.toString());
            return new SignWithImpl();
        }

        @Override
        public SignWith withStrongAlgorithms() {
            BuildSigningOutputStreamAPI.this.algorithmSuite = DefaultPGPAlgorithmSuites.strongSuite();
            LOGGER
                    .trace("use algorithms {}",
                            BuildSigningOutputStreamAPI.this.algorithmSuite.toString());
            return new SignWithImpl();
        }

        @Override
        public SignWith withOxAlgorithms() {
            BuildSigningOutputStreamAPI.this.algorithmSuite = DefaultPGPAlgorithmSuites.oxSuite();
            LOGGER
                    .trace("use algorithms {}",
                            BuildSigningOutputStreamAPI.this.toString());
            return new SignWithImpl();
        }

        @Override
        public SignWith withAlgorithms(final PGPAlgorithmSuite algorithmSuite) {
            requireNonNull(algorithmSuite, "algorithmSuite must not be null");

            BuildSigningOutputStreamAPI.this.algorithmSuite = algorithmSuite;
            LOGGER
                    .trace("use algorithms {}",
                            BuildSigningOutputStreamAPI.this.algorithmSuite.toString());
            return new SignWithImpl();
        }


        final class SignWithImpl implements SignWith {

            @Override
            public Armor andSignWith(String userId) throws IOException, PGPException {

                Preconditions.checkState(signingConfig.getSecretKeyRings() != null,
                        "signingConfig.getSecretKeyRings() must not be null");

                final PGPPublicKey signingKeyPubKey = getKeySelectionStrategy()
                        .selectPublicKey(PURPOSE.FOR_SIGNING, userId, signingConfig);

                if (signingKeyPubKey == null) {
                    throw new PGPException(
                            "No (suitable) public key for signing with '" + userId + "' found");
                }

                final PGPSecretKey signingKey = signingConfig.getSecretKeyRings()
                        .getSecretKey(signingKeyPubKey.getKeyID());
                if (signingKey == null) {
                    throw new PGPException(
                            "No (suitable) secret key for signing with " + userId
                                    + " found (public key exists!)");
                }

                BuildSigningOutputStreamAPI.this.signWith = userId;
                LOGGER.trace("sign with {}", BuildSigningOutputStreamAPI.this.signWith);
                return new ArmorImpl();
            }

            public final class ArmorImpl implements Armor {

                @Override
                public Build binaryOutput() {
                    BuildSigningOutputStreamAPI.this.armorOutput = false;
                    LOGGER.trace("binary output");
                    return new Builder();
                }

                @Override
                public Build armorAsciiOutput() {
                    BuildSigningOutputStreamAPI.this.armorOutput = true;
                    LOGGER.trace("ascii armor output");
                    return new Builder();
                }


                public final class Builder implements Build {

                    @Override
                    public OutputStream andWriteTo(OutputStream sinkForSignedData)
                            throws PGPException, SignatureException, NoSuchAlgorithmException,
                            NoSuchProviderException, IOException {
                        BuildSigningOutputStreamAPI.this.sinkForSignedData = sinkForSignedData;
                        return PGPSigningStream.create(
                                BuildSigningOutputStreamAPI.this.signingConfig,
                                BuildSigningOutputStreamAPI.this.algorithmSuite,
                                BuildSigningOutputStreamAPI.this.signWith,
                                BuildSigningOutputStreamAPI.this.sinkForSignedData,
                                getKeySelectionStrategy(),
                                BuildSigningOutputStreamAPI.this.armorOutput);

                    }
                }
            }

        }
    }
}
