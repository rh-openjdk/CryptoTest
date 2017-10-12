package cryptotest.tests;

import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.TestResult;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.CertificateException;

public class TrustManagerFactoryTests extends AlgorithmTest {
    public static void main(String[] args) {
        TestResult r = new TrustManagerFactoryTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws AlgorithmInstantiationException, AlgorithmRunException {
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(alias, service.getProvider());

            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, new char[]{104, 111, 118, 110, 111});

            trustManagerFactory.init(ks);
            TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();

            if (trustManagers == null || trustManagers.length == 0) {
                throw new UnsupportedOperationException("trustManagers are null or 0 length for " + service.getAlgorithm() + " in"
                        + service.getProvider().getName());
            }
        } catch (CertificateException | KeyStoreException | IOException e) {
            throw new AlgorithmRunException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new AlgorithmInstantiationException(e);
        }
    }
}
