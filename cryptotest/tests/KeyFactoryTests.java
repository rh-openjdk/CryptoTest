package cryptotest.tests;

import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.KeysNaiveGenerator;
import cryptotest.utils.TestResult;
import cryptotest.utils.Misc;

import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAMultiPrimePrivateCrtKey;
import java.security.spec.*;

import static java.math.BigInteger.ONE;

public class KeyFactoryTests extends AlgorithmTest {

    public static void main(String[] args) {
        TestResult r = new KeyFactoryTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws AlgorithmInstantiationException,
            AlgorithmRunException {
        try {
            Provider p = service.getProvider();
            boolean pkcs11fips = Misc.isPkcs11Fips(p);
            KeyFactory keyFactory = KeyFactory.getInstance(alias, p);
            KeySpec privateKeySpec = null;
            KeySpec publicKeySpec = null;
            Key translated = null;

            if (service.getAlgorithm().contains("DSA")) {
                KeyPair kp = KeysNaiveGenerator.getDsaKeyPair(p);
                translated = keyFactory.translateKey(kp.getPublic());
                if (!pkcs11fips) {
                    // pkcs11 provider in FIPS mode cannot obtain RAW keys
                    privateKeySpec = keyFactory.getKeySpec(kp.getPrivate(), DSAPrivateKeySpec.class);
                    publicKeySpec = keyFactory.getKeySpec(kp.getPublic(), DSAPublicKeySpec.class);
                }
            } else if (service.getAlgorithm().contains("RSASSA-PSS")) {
                KeyPairGenerator kpg = KeysNaiveGenerator.getKeyPairGenerator("RSASSA-PSS", p);
                KeyPair kp = kpg.generateKeyPair();
                translated = keyFactory.translateKey(kp.getPublic());
                if (!pkcs11fips) {
                    // pkcs11 provider in FIPS mode cannot obtain RAW keys
                    privateKeySpec = keyFactory.getKeySpec(kp.getPrivate(), RSAPrivateKeySpec.class);
                    publicKeySpec = keyFactory.getKeySpec(kp.getPublic(), RSAPublicKeySpec.class);
                }
            } else if (service.getAlgorithm().contains("X25519")) {
                KeyPairGenerator kpg = KeysNaiveGenerator.getKeyPairGenerator("X25519", p);
                KeyPair kp = kpg.generateKeyPair();
                translated = keyFactory.translateKey(kp.getPublic());
                if (!pkcs11fips) {
                    // pkcs11 provider in FIPS mode cannot obtain RAW keys
                    privateKeySpec = keyFactory.getKeySpec(kp.getPrivate(), PKCS8EncodedKeySpec.class);
                    publicKeySpec = keyFactory.getKeySpec(kp.getPublic(), X509EncodedKeySpec.class);
                }
            } else if (service.getAlgorithm().contains("X448")) {
                KeyPairGenerator kpg = KeysNaiveGenerator.getKeyPairGenerator("X448", p);
                KeyPair kp = kpg.generateKeyPair();
                translated = keyFactory.translateKey(kp.getPublic());
                if (!pkcs11fips) {
                    // pkcs11 provider in FIPS mode cannot obtain RAW keys
                    privateKeySpec = keyFactory.getKeySpec(kp.getPrivate(), PKCS8EncodedKeySpec.class);
                    publicKeySpec = keyFactory.getKeySpec(kp.getPublic(), X509EncodedKeySpec.class);
                }
            } else if (service.getAlgorithm().contains("XDH")) {
                KeyPairGenerator kpg = KeysNaiveGenerator.getKeyPairGenerator("XDH", p);
                KeyPair kp = kpg.generateKeyPair();
                translated = keyFactory.translateKey(kp.getPublic());
                if (!pkcs11fips) {
                    // pkcs11 provider in FIPS mode cannot obtain RAW keys
                    privateKeySpec = keyFactory.getKeySpec(kp.getPrivate(), PKCS8EncodedKeySpec.class);
                    publicKeySpec = keyFactory.getKeySpec(kp.getPublic(), X509EncodedKeySpec.class);
                }
            } else if (service.getAlgorithm().contains("RSA")) {
                KeyPair kp = KeysNaiveGenerator.getRsaKeyPair(p);
                translated = keyFactory.translateKey(kp.getPublic());
                if (!pkcs11fips) {
                    // pkcs11 provider in FIPS mode cannot obtain RAW keys
                    privateKeySpec = keyFactory.getKeySpec(kp.getPrivate(), RSAPrivateKeySpec.class);
                    publicKeySpec = keyFactory.getKeySpec(kp.getPublic(), RSAPublicKeySpec.class);
                }
            } else if (service.getAlgorithm().contains("EC")) {
                KeyPair keyPair = KeysNaiveGenerator.getKeyPairGenerator("EC", p).genKeyPair();
                translated = keyFactory.translateKey(keyPair.getPublic());
                if (p.getName().equals("SunEC")) {
                    // These classes are specific to SunEC provider
                    ECPrivateKey ecPrivateKey = ((ECPrivateKey) keyPair.getPrivate());
                    ECPublicKey ecPublicKey = ((ECPublicKey) keyPair.getPublic());
                    privateKeySpec = new ECPrivateKeySpec(ONE, ecPrivateKey.getParams());
                    publicKeySpec = new ECPublicKeySpec(ecPublicKey.getW(), ecPublicKey.getParams());
                }
            } else if (service.getAlgorithm().contains("DiffieHellman") || service.getAlgorithm().contains("DH")) {
                KeyPair kp = KeysNaiveGenerator.getKeyPairGenerator("DiffieHellman", p).genKeyPair();
                translated = keyFactory.translateKey(kp.getPublic());
                if (!pkcs11fips) {
                    // pkcs11 provider in FIPS mode cannot obtain RAW keys
                    privateKeySpec = keyFactory.getKeySpec(kp.getPrivate(), DHPrivateKeySpec.class);
                    publicKeySpec = keyFactory.getKeySpec(kp.getPublic(), DHPublicKeySpec.class);
                }
            } else if (service.getAlgorithm().contains("DES")) {
                privateKeySpec = new DESKeySpec(new byte[]{1, 2, 3, 4, 5, 6, 7});
                publicKeySpec = new DESKeySpec(new byte[]{1, 2, 3, 4, 5, 6, 7});
                translated = keyFactory.translateKey(KeysNaiveGenerator.getDesKey(p));
            }
            if (translated == null) {
                throw new UnsupportedOperationException("Tranlated key is null for " + service.getAlgorithm() + " in"
                        + service.getProvider().getName());
            }
            /*
                this check is skipped for pkcs11 provider in FIPS mode,
                because we cannot obtain KeySpecs (RAW keys) there
            */
            if (!pkcs11fips && (keyFactory.generatePrivate(privateKeySpec) == null || keyFactory.generatePublic(publicKeySpec) ==
                    null)) {
                throw new UnsupportedOperationException("Generated key is null for " + service.getAlgorithm() + " in"
                        + service.getProvider().getName());
            }
        } catch (NoSuchAlgorithmException e) {
            throw new AlgorithmInstantiationException(e);
        } catch (UnsupportedOperationException | InvalidKeySpecException | InvalidKeyException e) {
            throw new AlgorithmRunException(e);
        }
    }
}
