package cryptotest.tests;

import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.KeysNaiveGenerator;
import cryptotest.utils.TestResult;
import sun.security.x509.X509CertImpl;

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

            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, new char[]{104, 111, 118, 110, 111});
            ks.setCertificateEntry("bbb", new DummyCertificate());

            CertStore cs = CertStore.getInstance("Collection", new CollectionCertStoreParameters(Arrays.asList(new DummyCertificate(), new DummyCertificate())));


            Set<TrustAnchor> trustAnchors = new HashSet<>();
            trustAnchors.add(new TrustAnchor(new DummyCertificate(), null));

            PKIXBuilderParameters params = new PKIXBuilderParameters(ks, new X509CertSelector() {
                @Override
                public boolean match(Certificate cert) {
                    return true;
                }
            });
            params.addCertStore(cs);


            certPathBuilder.build(params);
        } catch (IOException | CertificateException | InvalidAlgorithmParameterException | CertPathBuilderException | KeyStoreException e) {
            throw new AlgorithmRunException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new AlgorithmInstantiationException(e);
        }
    }

    private static class DummyCertificate extends X509CertImpl {

        private final KeyPair keyPair = KeysNaiveGenerator.getRsaKeyPair();

        private DummyCertificate() throws NoSuchAlgorithmException {}

        @Override
        public PublicKey getPublicKey() {
            return keyPair.getPublic();
        }

        @Override
        public X500Principal getIssuerX500Principal() {
            return new X500Principal("CN=Jon");
        }

        @Override
        public X500Principal getSubjectX500Principal() {
            return new X500Principal("CN=Doe");
        }
    }
}
