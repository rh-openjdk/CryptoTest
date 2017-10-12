package cryptotest.tests;

import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.TestResult;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class SSLContextTests extends AlgorithmTest {
    private final SecureRandom random = new SecureRandom(new byte[]{6, 6, 6});

    public static void main(String[] args) {
        TestResult r = new SSLContextTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws AlgorithmInstantiationException,
            AlgorithmRunException {
        try {
            SSLContext sslContext = SSLContext.getInstance(alias, service.getProvider());

            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, new char[]{104, 111, 118, 110, 111});

            KeyManagerFactory keyManagerFactory = KeyManagerFactory
                    .getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, new char[]{104, 111, 118, 110, 111});

            TrustManagerFactory trustManagerFactory = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(keyStore);

            //Default SSLContext is initialized automatically
            if (!service.getAlgorithm().equals("Default")) {
                sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), random);
            }

            SSLEngine sslEngine = sslContext.createSSLEngine();
            if (sslEngine == null) {
                throw new UnsupportedOperationException("sslEngine can't be created for " + service.getAlgorithm() +
                        " in" + service.getProvider().getName());
            }
        } catch (IOException | CertificateException | UnrecoverableKeyException | KeyManagementException |
                KeyStoreException e) {
            throw new AlgorithmRunException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new AlgorithmInstantiationException(e);
        }
    }
}
