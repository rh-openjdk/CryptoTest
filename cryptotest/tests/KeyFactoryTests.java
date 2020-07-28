package cryptotest.tests;

import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.KeysNaiveGenerator;
import cryptotest.utils.TestResult;

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
            KeyFactory keyFactory = KeyFactory.getInstance(alias, service.getProvider());
            KeySpec privateKeySpec;
            KeySpec publicKeySpec;

            if (service.getAlgorithm().contains("DSA")) {
                KeyPair kp = KeysNaiveGenerator.getDsaKeyPair(service.getProvider());
                privateKeySpec = keyFactory.getKeySpec(kp.getPrivate(), DSAPrivateKeySpec.class);
                publicKeySpec = keyFactory.getKeySpec(kp.getPublic(), DSAPublicKeySpec.class);
            }else if (service.getAlgorithm().contains("RSASSA-PSS")) {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSASSA-PSS", service.getProvider());
                KeyPair kp = kpg.generateKeyPair();
                privateKeySpec = keyFactory.getKeySpec(kp.getPrivate(), RSAPrivateKeySpec.class);
                publicKeySpec = keyFactory.getKeySpec(kp.getPublic(), RSAPublicKeySpec.class);

            } else if (service.getAlgorithm().contains("X25519")) {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519", service.getProvider());
                KeyPair kp = kpg.generateKeyPair();
                privateKeySpec = keyFactory.getKeySpec(kp.getPrivate(), PKCS8EncodedKeySpec.class);
                publicKeySpec = keyFactory.getKeySpec(kp.getPublic(), X509EncodedKeySpec.class);

            } else if (service.getAlgorithm().contains("X448")) {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("X448", service.getProvider());
                KeyPair kp = kpg.generateKeyPair();
                privateKeySpec = keyFactory.getKeySpec(kp.getPrivate(), PKCS8EncodedKeySpec.class);
                publicKeySpec = keyFactory.getKeySpec(kp.getPublic(), X509EncodedKeySpec.class);

            } else if (service.getAlgorithm().contains("XDH")) {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH", service.getProvider());
                KeyPair kp = kpg.generateKeyPair();
                privateKeySpec = keyFactory.getKeySpec(kp.getPrivate(), PKCS8EncodedKeySpec.class);
                publicKeySpec = keyFactory.getKeySpec(kp.getPublic(), X509EncodedKeySpec.class);

            } else if (service.getAlgorithm().contains("RSA")) {
                KeyPair kp = KeysNaiveGenerator.getRsaKeyPair(service.getProvider());
                privateKeySpec = keyFactory.getKeySpec(kp.getPrivate(), RSAPrivateKeySpec.class);
                publicKeySpec = keyFactory.getKeySpec(kp.getPublic(), RSAPublicKeySpec.class);
            } else if (service.getAlgorithm().contains("EC")) {
                KeyPair keyPair = KeyPairGenerator.getInstance("EC", service.getProvider()).genKeyPair();
                ECPrivateKey ecPrivateKey = ((ECPrivateKey) keyPair.getPrivate());
                ECPublicKey ecPublicKey = ((ECPublicKey) keyPair.getPublic());
                privateKeySpec = new ECPrivateKeySpec(ONE, ecPrivateKey.getParams());
                publicKeySpec = new ECPublicKeySpec(ecPublicKey.getW(), ecPublicKey.getParams());
            } else if (service.getAlgorithm().contains("DiffieHellman") || service.getAlgorithm().contains("DH")) {
                KeyPair kp = KeyPairGenerator.getInstance("DiffieHellman").genKeyPair();
                privateKeySpec = keyFactory.getKeySpec(kp.getPrivate(), DHPrivateKeySpec.class);
                publicKeySpec = keyFactory.getKeySpec(kp.getPublic(), DHPublicKeySpec.class);
            } else if (service.getAlgorithm().contains("DES")) {
                privateKeySpec = new DESKeySpec(new byte[]{1, 2, 3});
                publicKeySpec = new DESKeySpec(new byte[]{1, 2, 3});
            } else {
                privateKeySpec = null;
                publicKeySpec = null;
            }

            if (keyFactory.generatePrivate(privateKeySpec) == null || keyFactory.generatePublic(publicKeySpec) ==
                    null) {
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
