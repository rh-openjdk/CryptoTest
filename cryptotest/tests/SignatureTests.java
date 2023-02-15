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
 * @bug 1022017
 * @library /
 * @build cryptotest.tests.SignatureTests
 *        cryptotest.Settings
 *        cryptotest.utils.AlgorithmIgnoredException
 *        cryptotest.utils.AlgorithmInstantiationException
 *        cryptotest.utils.AlgorithmRunException
 *        cryptotest.utils.AlgorithmTest
 *        cryptotest.utils.KeysNaiveGenerator
 *        cryptotest.utils.TestResult
 * @run main/othervm cryptotest.tests.SignatureTests
 */

package cryptotest.tests;

import cryptotest.utils.AlgorithmIgnoredException;
import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import static cryptotest.utils.KeysNaiveGenerator.getDsaPrivateKey;
import static cryptotest.utils.KeysNaiveGenerator.getEcPrivateKey;
import static cryptotest.utils.KeysNaiveGenerator.getRsaPrivateKey;
import static cryptotest.utils.KeysNaiveGenerator.getDsaPrivateKey1024;
import cryptotest.utils.TestResult;
import cryptotest.utils.Misc;

import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/*
 * IwishThisCouldBeAtTest
 */
public class SignatureTests extends AlgorithmTest {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        TestResult r = new SignatureTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws AlgorithmInstantiationException, AlgorithmRunException {
        try {
            if (Misc.isPkcs11Fips(service.getProvider())
                && service.getAlgorithm().contains("SHA3-")) {
                // skip: NSS does not support SHA3 (yet)
                // See: https://issues.redhat.com/browse/OPENJDK-826
                return;
            }
            Signature sig = Signature.getInstance(alias, service.getProvider());
            //most of them are happy with rsa...
            PrivateKey key = getRsaPrivateKey(service.getProvider());
            if (service.getAlgorithm().contains("EC")) {
                key = getEcPrivateKey(service.getProvider());
            } else if (service.getAlgorithm().equals("Ed25519") || service.getAlgorithm().equals("EdDSA") || service.getAlgorithm().equals("Ed448")) {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(service.getAlgorithm(), service.getProvider());
                KeyPair kp = kpg.generateKeyPair();
                key = kp.getPrivate();
            } else if (service.getAlgorithm().contains("DSA")) {
                //if (service.getAlgorithm().contains("SHA1")) {
                    /* SHA1 is not sufficient for default DSA key size,
                       throwing:
                       java.security.InvalidKeyException: The security strength of SHA-1 digest algorithm is not sufficient for this key size

                       See:
                       https://bugs.java.com/view_bug.do?bug_id=8184341
                       http://hg.openjdk.java.net/jdk8u/jdk8u-dev/jdk/file/8a97a690a0b3/src/share/classes/sun/security/provider/DSA.java#l104

                       1024-bits is also needed for pkcs11 in fips mode, default size does not work there
                    */
                    key = getDsaPrivateKey1024(service.getProvider());
                    /*
                } else {
                    key = getDsaPrivateKey(service.getProvider());
                }
                */
            } else if (service.getAlgorithm().contains("RSASSA-PSS")){
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", service.getProvider());
                KeyPair kp = kpg.generateKeyPair();
                key = kp.getPrivate();
                PSSParameterSpec pssParam;
                // See:
                // https://github.com/openjdk/jdk11u/blob/73eef16128417f4a489c4dde47383bb4a00f39d4/src/java.base/share/classes/java/security/spec/PSSParameterSpec.java#L167
                // https://github.com/openjdk/jdk11u/blob/73eef16128417f4a489c4dde47383bb4a00f39d4/test/jdk/sun/security/mscapi/InteropWithSunRsaSign.java#L55
                if (service.getAlgorithm().contains("SHA512")) {
                    pssParam = new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, PSSParameterSpec.TRAILER_FIELD_BC);
                } else if (service.getAlgorithm().contains("SHA384")) {
                    pssParam = new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, PSSParameterSpec.TRAILER_FIELD_BC);
                } else if (service.getAlgorithm().contains("SHA256")) {
                    pssParam = new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, PSSParameterSpec.TRAILER_FIELD_BC);
                } else if (service.getAlgorithm().contains("SHA224")) {
                    pssParam = new PSSParameterSpec("SHA-224", "MGF1", MGF1ParameterSpec.SHA224, 28, PSSParameterSpec.TRAILER_FIELD_BC);
                } else {
                    // defaults (SHA1)
                    pssParam = new PSSParameterSpec(20);
                }
                sig.setParameter(pssParam);
            }
            sig.initSign(key);
            //NONEwithDSA needs 20bytes
            byte[] b = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
                15, 16, 17, 18, 19, 20};
            sig.update(b);
            byte[] res = sig.sign();
            AlgorithmTest.printResult(res);
        } catch (NoSuchAlgorithmException ex) {
            throw new AlgorithmInstantiationException(ex);
        } catch (InvalidKeyException | UnsupportedOperationException | InvalidParameterException | SignatureException |
                InvalidAlgorithmParameterException | ProviderException ex) {
            if (Misc.isPkcs11Fips(service.getProvider())
                && ex.getMessage().startsWith("Unknown mechanism:")
                && (service.getAlgorithm().equals("SHA512withDSA")
                    || service.getAlgorithm().equals("SHA384withDSA")
                    || service.getAlgorithm().equals("SHA256withDSA")
                    || service.getAlgorithm().equals("SHA224withDSA"))) {
                /* NOTABUG, see:
                   https://bugzilla.redhat.com/show_bug.cgi?id=1868744
                */
                throw new AlgorithmIgnoredException();
            }
            throw new AlgorithmRunException(ex);
        }

    }

    @Override
    public String getTestedPart() {
        return "Signature";
    }

}
