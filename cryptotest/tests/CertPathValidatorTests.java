package cryptotest.tests;

import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.TestResult;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 
 * The root certificate must be marked as a CA, which can be done by issuing this command:
 * keytool -genkeypair -alias <ALIAS> -keystore <KEYSTORE> -storepass <PASSWORD> -keypass <KEY_PASSWORD> -ext bc=ca:true
 * 
 * ugh, see regenerateTestStoreChain1.sh
 * 
 */

public class CertPathValidatorTests extends AlgorithmTest {

    private KeyStore caStore;

    public static void main(String[] args) {
        TestResult r = new CertPathValidatorTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    @Override
    public String getTestedPart() {
        return "CertPathValidator";
    }

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws AlgorithmInstantiationException, AlgorithmRunException {
        try {
            loadKeyStore();

            CertPathValidator pathValidator = CertPathValidator.getInstance(alias, service.getProvider());
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            CertPath certPath = factory.generateCertPath(getCertificates());
            PKIXParameters certPathParams = new PKIXParameters(
                    Collections.
                            singleton(new TrustAnchor((X509Certificate) caStore.getCertificate("root"),
                                    null))
            );
            //skip revocation status check, test otherwise fails
            certPathParams.setRevocationEnabled(false);
            CertPathValidatorResult validatorResult = pathValidator.validate(certPath, certPathParams);
        } catch (NoSuchAlgorithmException | CertificateException | InvalidAlgorithmParameterException | KeyStoreException
                | IOException | UnrecoverableKeyException ex) {
            throw new AlgorithmInstantiationException(ex);
        } catch (CertPathValidatorException ex) {
            throw new AlgorithmRunException(ex);
        }
    }

    private void loadKeyStore() throws KeyStoreException, IOException,
            NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {
        InputStream is = CertPathValidatorTests.class.getResourceAsStream("test.jks");
        KeyStore caKs = KeyStore.getInstance("JKS");
        caKs.load(is, "password".toCharArray());
        caStore = caKs;
    }

    private List<X509Certificate> getCertificates() throws KeyStoreException, IOException,
            NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {
        List<X509Certificate> result = new ArrayList<>();
        //root certificate does not need to be added as the algorithm
        //can already determine whether this last intermediate cert has been
        //signed by a root CA or not
        result.add((X509Certificate) caStore.getCertificate("server")); //order is important
        result.add((X509Certificate) caStore.getCertificate("ca"));
        return result;
    }
}
