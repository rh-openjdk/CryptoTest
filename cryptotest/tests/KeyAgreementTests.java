package cryptotest.tests;

import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.TestResult;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyAgreement;
import com.sun.crypto.provider.DHKeyPairGenerator;
import sun.security.ec.ECKeyPairGenerator;
import cryptotest.utils.KeysNaiveGenerator;
import cryptotest.utils.Misc;

public class KeyAgreementTests extends AlgorithmTest {

    public static void main(String[] args) {
        TestResult r = new KeyAgreementTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws AlgorithmInstantiationException, AlgorithmRunException {
                
        try {
            KeyAgreement kagr = KeyAgreement.getInstance(alias, service.getProvider());
            KeyPair keypair;
            String keyType = alias;
            if ("ECDH".equals(keyType)) {
                keyType = "EC";
            }
            keypair = KeysNaiveGenerator.getKeyPairGenerator(keyType, service.getProvider()).generateKeyPair();
            PrivateKey pk = keypair.getPrivate();
            printResult(pk.getEncoded());
            PublicKey pubkey = keypair.getPublic();
            printResult(pubkey.getEncoded());
            kagr.init(pk);
            // do not print result, can return none (see the documentation)
            kagr.doPhase(pubkey, true);

            if (!Misc.isPkcs11Fips(service.getProvider())) {
                /* pkcs11 in FIPS mode cannot obtain raw secrets (CKR_ATTRIBUTE_SENSITIVE)
                   https://hg.openjdk.java.net/jdk8u/jdk8u/jdk/file/4687075d8ccf/src/share/classes/sun/security/pkcs11/P11ECDHKeyAgreement.java#l140
                */
                printResult(kagr.generateSecret());
            } else {
                /* pkcs11 only supports TlsPremasterSecret algorithm, see:
                   https://hg.openjdk.java.net/jdk8u/jdk8u/jdk/file/4687075d8ccf/src/share/classes/sun/security/pkcs11/P11ECDHKeyAgreement.java#l172
                */
                printResult(kagr.generateSecret("TlsPremasterSecret").toString());
            }
        } catch (NoSuchAlgorithmException ex) {
            throw new AlgorithmInstantiationException(ex);
        } catch (InvalidKeyException|NullPointerException ex) {
            throw new AlgorithmRunException(ex);
        }
    }
   
    @Override
    public String getTestedPart() {
        return "KeyAgreement";
        
        
    }

}
