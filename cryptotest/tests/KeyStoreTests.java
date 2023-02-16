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

/*
 * @test
 * @modules java.base/java.security:open
 * @bug 1422738
 * @library /
 * @build cryptotest.tests.KeyStoreTests
 *        cryptotest.Settings
 *        cryptotest.utils.AlgorithmIgnoredException
 *        cryptotest.utils.AlgorithmInstantiationException
 *        cryptotest.utils.AlgorithmRunException
 *        cryptotest.utils.AlgorithmTest
 *        cryptotest.utils.Misc
 *        cryptotest.utils.TestResult
 * @run main/othervm cryptotest.tests.KeyStoreTests
 */

package cryptotest.tests;

import cryptotest.utils.AlgorithmIgnoredException;
import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.Misc;
import cryptotest.utils.TestResult;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

/*
 * IwishThisCouldBeAtTest
 */
public class KeyStoreTests extends AlgorithmTest {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        TestResult r = new KeyStoreTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws AlgorithmInstantiationException, AlgorithmRunException {
        try {
            if (service.getProvider().getName().equals("SunMSCAPI")
                && alias.toUpperCase().endsWith("-LOCALMACHINE")
                && !Misc.hasWindowsAdmin()) {
                // SunMCAPI *-LOCALMACHINE keystores require Admin privileges:
                // https://github.com/openjdk/jdk/blob/9b911b492f56fbf94682535a1d20dde07c62940f/test/jdk/sun/security/mscapi/AllTypes.java#L48
                throw new AlgorithmIgnoredException();
            }
            KeyStore ks = KeyStore.getInstance(alias, service.getProvider());
            char[] pw = new char[]{'a', 'b'};
            if (alias.startsWith("PKCS11")) {
                // in case of PKCS11 this is pin to PKCS11 token
                // (empty in default configuration)
                pw = new char[]{};
            }
            ks.load(null, pw);
            printResult(ks.size());
            printResult(ks.getType());
            //creating cert is another story, so letting this be
        } catch (KeyStoreException | NoSuchAlgorithmException ex) {
            throw new AlgorithmInstantiationException(ex);
        } catch (UnsupportedOperationException | InvalidParameterException | ProviderException | IOException | CertificateException ex) {
            throw new AlgorithmRunException(ex);
        }
    }

    @Override
    public String getTestedPart() {
        return "KeyStore";
    }

}
