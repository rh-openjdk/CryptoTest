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
 * @bug 1422738
 * @library /
 * @build cryptotest.tests.KeyAgreementTests
 *        cryptotest.Settings
 *        cryptotest.utils.AlgorithmInstantiationException
 *        cryptotest.utils.AlgorithmRunException
 *        cryptotest.utils.AlgorithmTest
 *        cryptotest.utils.KeysNaiveGenerator
 *        cryptotest.utils.Misc
 *        cryptotest.utils.TestResult
 * @run main/othervm cryptotest.tests.KeyAgreementTests
 */

package cryptotest.tests;

import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.TestResult;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyAgreement;
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
