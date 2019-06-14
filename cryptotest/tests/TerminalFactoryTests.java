/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptotest.tests;

import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.TestResult;
import java.security.Provider;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.TerminalFactory;

/**
 * This test was supposed to test PCSC Terminal factory. Unfortunately, it can't be inicialized with PCSC provider as
 * usual for some reason, we are initing it with default method (that uses PCSC provider anyways).
 * However, this testcase no longer serves its purpose, if other providers appear.
 * @author Zdeněk Žamberský, Petra Mikova
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
    protected void checkAlgorithm(Provider.Service service, String alias) throws AlgorithmRunException {
            TerminalFactory tc
                    = TerminalFactory
                            .getDefault();
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
        }


    @Override
    public String getTestedPart() {
        return "TerminalFactory";
    }

}
