/*
 * The MIT License
 *
 * Copyright 2022 Red Hat, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
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
