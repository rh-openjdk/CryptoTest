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
 * @bug 1022017
 * @library /
 * @build cryptotest.tests.TrustManagerFactoryTests
 *        cryptotest.Settings
 *        cryptotest.utils.AlgorithmInstantiationException
 *        cryptotest.utils.AlgorithmRunException
 *        cryptotest.utils.AlgorithmTest
 *        cryptotest.utils.TestResult
 * @run main/othervm cryptotest.tests.TrustManagerFactoryTests
 */

package cryptotest.tests;

import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.TestResult;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.CertificateException;

public class TrustManagerFactoryTests extends AlgorithmTest {
    public static void main(String[] args) {
        TestResult r = new TrustManagerFactoryTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws AlgorithmInstantiationException, AlgorithmRunException {
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(alias, service.getProvider());

            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, new char[]{104, 111, 118, 110, 111});

            trustManagerFactory.init(ks);
            TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();

            if (trustManagers == null || trustManagers.length == 0) {
                throw new UnsupportedOperationException("trustManagers are null or 0 length for " + service.getAlgorithm() + " in"
                        + service.getProvider().getName());
            }
        } catch (CertificateException | KeyStoreException | IOException e) {
            throw new AlgorithmRunException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new AlgorithmInstantiationException(e);
        }
    }
}
