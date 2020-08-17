package cryptotest.tests;

import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.KeysNaiveGenerator;
import cryptotest.utils.TestResult;
import sun.security.x509.X509CertImpl;
import java.security.cert.X509Certificate;
import java.io.InputStream;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class CertPathBuilderTests extends AlgorithmTest {

    public static void main(String[] args) {
        TestResult r = new CertPathBuilderTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws AlgorithmInstantiationException, AlgorithmRunException {
        try {
            CertPathBuilder certPathBuilder = CertPathBuilder.getInstance(alias, service.getProvider());

            InputStream is = CertPathValidatorTests.class.getResourceAsStream("test.jks");
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(is, "password".toCharArray());

            Certificate serverCrt = ks.getCertificate("server");
            Certificate caCrt = ks.getCertificate("ca");

            CertStore cs = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(
                    Arrays.asList(
                        serverCrt,
                        caCrt
                    )
                )
            );

            Set<TrustAnchor> trustAnchors = new HashSet<>();
            trustAnchors.add(new TrustAnchor((X509Certificate) caCrt, null));

            X509CertSelector target = new X509CertSelector();

            PKIXBuilderParameters params = new PKIXBuilderParameters(trustAnchors, target);
            params.addCertStore(cs);

            certPathBuilder.build(params);
        } catch (IOException | CertificateException | InvalidAlgorithmParameterException | CertPathBuilderException | KeyStoreException e ) {
            throw new AlgorithmRunException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new AlgorithmInstantiationException(e);
        }
    }

}
