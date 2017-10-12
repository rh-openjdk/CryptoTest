package cryptotest.tests;

import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.TestResult;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class KeyManagerFactoryTests extends AlgorithmTest {

    public static void main(String[] args) {
        TestResult r = new KeyManagerFactoryTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws AlgorithmInstantiationException,
            AlgorithmRunException {
        try {
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(alias, service.getProvider());

            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, new char[]{104, 111, 118, 110, 111});

            keyManagerFactory.init(ks, new char[]{112, 114, 100, 101, 108});

            KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();
            if (keyManagers == null || keyManagers.length == 0) {
                throw new UnsupportedOperationException("No KeyManagers for " + service.getAlgorithm() + " in" +
                        service.getProvider().getName());
            }
        } catch (UnsupportedOperationException | IOException | UnrecoverableKeyException | KeyStoreException |
                CertificateException e) {
            throw new AlgorithmRunException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new AlgorithmInstantiationException(e);
        }
    }
}
