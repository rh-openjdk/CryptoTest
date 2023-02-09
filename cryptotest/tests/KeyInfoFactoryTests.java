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
 *          java.base/com.sun.crypto.provider
 *          java.base/sun.security.internal.spec
 *          java.base/sun.security.ssl
 *          java.xml.crypto/org.jcp.xml.dsig.internal.dom
 * @bug 1022017
 * @library /
 * @build cryptotest.tests.KeyInfoFactoryTests
 *        cryptotest.Settings
 *        cryptotest.utils.AlgorithmInstantiationException
 *        cryptotest.utils.AlgorithmRunException
 *        cryptotest.utils.AlgorithmTest
 *        cryptotest.utils.KeysNaiveGenerator
 *        cryptotest.utils.TestResult
 * @run main/othervm cryptotest.tests.KeyInfoFactoryTests
 */

package cryptotest.tests;

import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.KeysNaiveGenerator;
import cryptotest.utils.TestResult;
import org.jcp.xml.dsig.internal.dom.DOMKeyName;

import javax.xml.crypto.NoSuchMechanismException;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyName;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.PGPData;
import javax.xml.crypto.dsig.keyinfo.RetrievalMethod;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.keyinfo.X509IssuerSerial;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Arrays;
import java.util.Collections;

public class KeyInfoFactoryTests extends AlgorithmTest {
    public static void main(String[] args) {
        TestResult r = new KeyInfoFactoryTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws AlgorithmInstantiationException,
            AlgorithmRunException {
        try {
            KeyInfoFactory keyInfoFactory = KeyInfoFactory.getInstance(alias, service.getProvider());

            KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(new DOMKeyName("blabol")));
            KeyName keyName = keyInfoFactory.newKeyName("blabol");
            PGPData pgpData = keyInfoFactory.newPGPData(new byte[]{1, 2, 3, 4, 5, 6, 7, 8});
            RetrievalMethod retrievalMethod = keyInfoFactory.newRetrievalMethod("bbb");
            KeyValue keyValue = null;
            try {
                keyValue = keyInfoFactory.newKeyValue(KeysNaiveGenerator.getRsaKeyPair(service.getProvider()).getPublic());
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            X509Data x509Data = keyInfoFactory.newX509Data(Arrays.asList(new byte[]{1, 2, 3, 4, 5, 6, 7, 8}));
            X509IssuerSerial x509IssuerSerial = keyInfoFactory.newX509IssuerSerial("CN=Jon Doe", BigInteger.ONE);

            if (keyInfo == null || keyName == null || pgpData == null || retrievalMethod == null || keyValue == null
                    || x509Data == null || x509IssuerSerial == null) {
                throw new UnsupportedOperationException("No key info for " + service.getAlgorithm() + " in" +
                        service.getProvider().getName());
            }
        } catch (NoSuchMechanismException e) {
            throw new AlgorithmInstantiationException(e);
        } catch (Exception e) {
            throw new AlgorithmRunException(e);
        }
    }
}
