package cryptotest.tests;

import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.TestResult;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;


public class KeyPairGeneratorTests extends AlgorithmTest {
    private final SecureRandom random = new SecureRandom(new byte[]{6, 6, 6});

    public static void main(String[] args) {
        TestResult r = new KeyPairGeneratorTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws
            AlgorithmInstantiationException, AlgorithmRunException {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(alias, service.getProvider());
            int keySize = 512;
            if (service.getAlgorithm().contains("EC")) {
                keySize = 256;
            } else if (service.getAlgorithm().contains("XDH") || service.getAlgorithm().contains("X25519")){
                // https://docs.oracle.com/en/java/javase/11/security/oracle-providers.html#GUID-B1F2B3F3-F2A4-4FF5-8887-3B3335343B2A
                keySize = 255;
            } else if (service.getAlgorithm().contains("X448")){
                // https://docs.oracle.com/en/java/javase/11/security/oracle-providers.html#GUID-B1F2B3F3-F2A4-4FF5-8887-3B3335343B2A
                keySize = 448;
            } else if (service.getAlgorithm().contains("DH") || service.getAlgorithm().contains("DiffieHellman")) {
                // DH < 2048 disabled in DEFAULT, FIPS
                // https://access.redhat.com/articles/3642912
                keySize = 2048;
            } else if (service.getAlgorithm().contains("RSA")) {
                keySize = 2048;
            }
            keyPairGenerator.initialize(keySize, random);
            KeyPair pair = keyPairGenerator.genKeyPair();

            if (pair == null || pair.getPrivate() == null || pair.getPublic() == null) {
                throw new UnsupportedOperationException("Generated key is null for " + service.getAlgorithm() + " in"
                        + service.getProvider().getName());
            }
        } catch (NoSuchAlgorithmException e) {
            throw new AlgorithmInstantiationException(e);
        } catch (UnsupportedOperationException e) {
            throw new AlgorithmRunException(e);
        }
    }
}
