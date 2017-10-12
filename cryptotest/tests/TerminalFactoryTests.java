/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptotest.tests;

import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.TestResult;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.TerminalFactory;

/**
 *
 * @author Zdeněk Žamberský
 */
public class TerminalFactoryTests extends AlgorithmTest {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        TestResult r = new TerminalFactoryTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws
            AlgorithmInstantiationException, AlgorithmRunException {
        try {
            TerminalFactory tc
                    = TerminalFactory
                            .getInstance(alias, null, service.getProvider());
            CardTerminals terminals = tc.terminals();
            try {
                terminals.list();
            } catch (CardException ex) {
                // we don't have smartcard readers attached to computer,
                // so exception is expected
                Throwable t = ex.getCause();
                if(t == null || !t.getMessage()
                        .equals("SCARD_E_NO_READERS_AVAILABLE")) {
                    // SCARD_E_NO_READERS_AVAILABLE is expected as cause
                    // otherwise throw AlgorithmRunException
                    throw new AlgorithmRunException(ex);
                }
                
            }
        } catch (NoSuchAlgorithmException ex) {
            throw new AlgorithmInstantiationException(ex);
        }
    }

    @Override
    public String getTestedPart() {
        return "TerminalFactory";
    }

}
