package cryptotest.tests;

import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.Misc;
import cryptotest.utils.TestResult;
import java.security.Provider;
import java.util.HashMap;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

public class SaslClientFactoryTests extends AlgorithmTest {

    public static void main(String[] args) {
        TestResult r = new SaslClientFactoryTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    @Override
    public String getTestedPart() {
        return "SaslClientFactory";
    }

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws AlgorithmInstantiationException, AlgorithmRunException {
        System.setProperty("java.security.krb5.conf",
                Misc.createTmpKrb5File().getPath());
        try {
            String[] mechanisms = new String[]{alias};
            SaslClient client = Sasl.createSaslClient(mechanisms, "user1",
                    "ldap", "127.0.0.1", new HashMap<String, Object>(), Misc.getNamePasswdRealmHandler()); //note that this ldap handler may use differrent replyes at the end (then kerberos one)
            if (client != null) {
                printResult("Mechanism is '" + client.getMechanismName()
                        + "' and authentication is " + (client.isComplete() ? "" : "NOT ")
                        + "complete");
            } else {
                throw new AlgorithmRunException(new RuntimeException(
                        String.format("client null, provider '%s' and alias '%s'", service.getAlgorithm(), alias)));
            }
        } catch (SaslException ex) {
            throw new AlgorithmInstantiationException(ex);
        }
    }
}
