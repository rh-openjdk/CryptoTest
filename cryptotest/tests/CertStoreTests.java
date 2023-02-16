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
 * @build cryptotest.tests.CertStoreTests
 *        cryptotest.Settings
 *        cryptotest.utils.AlgorithmInstantiationException
 *        cryptotest.utils.AlgorithmRunException
 *        cryptotest.utils.AlgorithmTest
 *        cryptotest.utils.TestResult
 * @run main/othervm cryptotest.tests.CertStoreTests
 */

package cryptotest.tests;

import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.TestResult;
import java.security.*;
import java.security.cert.CertSelector;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.LDAPCertStoreParameters;
import java.util.Arrays;
import java.util.Collection;

/*
 * IwishThisCouldBeAtTest
 */
public class CertStoreTests extends AlgorithmTest {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        TestResult r = new CertStoreTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws AlgorithmInstantiationException, AlgorithmRunException {
        try {
            CertStoreParameters p = null;
            if (alias.equals("LDAP")) {
                p = new LDAPCertStoreParameters();
                //this needs ldap server to finish
                return;
            } else {
                p = new CollectionCertStoreParameters();
            }
            CertStore ks = CertStore.getInstance(alias, p, service.getProvider());
            printResult(ks.getType());
            Collection<? extends java.security.cert.Certificate> cl = ks.getCertificates(new CertSelector() {
                @Override
                public boolean match(java.security.cert.Certificate cert) {
                    return true;
                }

                @Override
                public Object clone() {
                    try {
                        return super.clone();
                    } catch (Exception ex) {;
                        ex.printStackTrace();
                        return null;
                    }
                }
            });
            if (cl == null) {
                throw new AlgorithmRunException(new RuntimeException("Was nto possible to iterate through certstore"));
            }
            printResult(Arrays.toString(cl.toArray()));
        } catch (NoSuchAlgorithmException ex) {
            throw new AlgorithmInstantiationException(ex);
        } catch (Exception ex) {
            throw new AlgorithmRunException(ex);
        }
    }

    @Override

    public String getTestedPart() {
        return "CertStore";
    }

}
