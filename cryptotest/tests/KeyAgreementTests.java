package cryptotest.tests;

import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.TestResult;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import javax.crypto.KeyAgreement;
import com.sun.crypto.provider.DHKeyPairGenerator;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import sun.security.ec.ECKeyPairGenerator;

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
            if ("ECDH".equals(alias)) {
                keypair = new ECKeyPairGenerator().generateKeyPair();
                
            } else {
                keypair = new DHKeyPairGenerator().generateKeyPair();
            }
            PrivateKey pk = keypair.getPrivate();
            printResult(pk.getEncoded());
            PublicKey pubkey = keypair.getPublic();
            printResult(pubkey.getEncoded());
            kagr.init(pk);
            // do not print result, can return none (see the documentation)
            kagr.doPhase(pubkey, true);

            printResult(kagr.generateSecret());        
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
