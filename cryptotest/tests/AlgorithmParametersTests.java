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
 * @build cryptotest.tests.AlgorithmParametersTests
 *        cryptotest.Settings
 *        cryptotest.utils.AlgorithmInstantiationException
 *        cryptotest.utils.AlgorithmRunException
 *        cryptotest.utils.AlgorithmTest
 *        cryptotest.utils.TestResult
 * @run main/othervm cryptotest.tests.AlgorithmParametersTests
 */

package cryptotest.tests;

import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.TestResult;

import java.security.*;
import java.io.IOException;
import java.math.BigInteger;
import java.security.spec.*;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.RC2ParameterSpec;

/*
 * IwishThisCouldBeAtTest
 */
public class AlgorithmParametersTests extends AlgorithmTest {

    public static void main(String[] args) {
        TestResult r = new AlgorithmParametersTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws
            AlgorithmInstantiationException, AlgorithmRunException {
        try {
            AlgorithmParameters c = AlgorithmParameters.getInstance(alias, service.getProvider());
            AlgorithmParameterSpec params = null;
            //order important!
            if (service.getAlgorithm().contains("DSA")) {
                params = new DSAParameterSpec(BigInteger.ONE, BigInteger.ONE, BigInteger.ONE);
            } else if (service.getAlgorithm().contains("RSASSA")) {
                params = new PSSParameterSpec(10);
            } else if (service.getAlgorithm().contains("PBES2")) {
                //it looks like bug, PBES2 in its internal except name like PBES2WithHmacSHAxyzAES_abc
                params = new PBEParameterSpec(new byte[]{1, 2, 3, 4}, 10);
            } else if (service.getAlgorithm().contains("PBEWithHmacSHA") && service.getAlgorithm().contains("AES")) {
                // this constructoris useles, we ened the second params anyway
                //params = new PBEParameterSpec(new byte[]{1, 2, 3, 4}, 10);
                IvParameterSpec interParams = new IvParameterSpec(new byte[]{1, 2, 3, 4, 5, 6, 7, 8});
                params = new PBEParameterSpec(new byte[]{1, 2, 3, 4}, 10, interParams);
            } else if (service.getAlgorithm().contains("PBEWithHmacSHA")) {
                params = new IvParameterSpec(new byte[]{1, 2, 3, 4, 5, 6, 7, 8});
            } else if (service.getAlgorithm().contains("DiffieHellman")) {
                params = new DHParameterSpec(BigInteger.ONE, BigInteger.ONE);
            } else if (service.getAlgorithm().contains("GCM")) {
                //thjis construtor takes all, but when dec getEncoding, first number metters
                params = new GCMParameterSpec(110, new byte[]{1, 2, 3, 4, 5, 6, 7, 8});
            } else if (service.getAlgorithm().contains("PBE")) {
                params = new PBEParameterSpec(new byte[]{1, 2, 3, 4}, 10);
            } else if (service.getAlgorithm().contains("AES")) {
                params = new IvParameterSpec(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
            } else if (service.getAlgorithm().contains("RC2")) {
                //why does this constructor exists?!?!?! throws npe later..
                //params = new RC2ParameterSpec(1);
                params = new RC2ParameterSpec(1, new byte[]{1, 2, 3, 4, 5, 6, 7, 8});
            } else if (service.getAlgorithm().contains("Blowfish") || service.getAlgorithm().contains("DES")) {
                params = new IvParameterSpec(new byte[]{1, 2, 3, 4, 5, 6, 7, 8});
            } else if (service.getAlgorithm().contains("OAEP")) {
                params = new OAEPParameterSpec("sha1", "MGF1", new MGF1ParameterSpec("sha1"), new PSource.PSpecified(new byte[]{1, 2, 3}));
            } else if (service.getAlgorithm().contains("EC")) {
                params = new ECGenParameterSpec("1.2.840.10045.3.1.7");
            } else if (service.getAlgorithm().contains("ChaCha20")){
                // must be 12 bytes long
                params = new IvParameterSpec(new byte[]{1,2,3,4,5,6,7,8,9,10,11,12});
            }

            c.init(params);
            if (!service.getAlgorithm().contains("PBES2")) {
                printResult(c.getEncoded());
                AlgorithmParameters c2 = AlgorithmParameters.getInstance(alias, service.getProvider());
                byte[] encodedParams = c.getEncoded();
                c2.init(encodedParams);
            } else {
                //pbes2 is broken. Its name should be something like PBES2WithHmacSHAxyzAES_lmn bt is not
                //maybe it got used somewhere internally, so lets now live with init only
                printResult(service.getAlgorithm() + ", " + alias + " inited, rub skipped");
            }

        } catch (IOException | InvalidParameterSpecException ex) {
            throw new AlgorithmInstantiationException(ex);
        } catch (Exception ex) {
            throw new AlgorithmRunException(ex);
        }

    }

    @Override
    public String getTestedPart() {
        return "AlgorithmParameters";
    }

}
