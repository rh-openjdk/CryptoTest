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

import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.KeysNaiveGenerator;
import cryptotest.utils.TestResult;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.PBEParameterSpec;

/*
 * IwishThisCouldBeAtTest
 */
public class MacTests extends AlgorithmTest {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        TestResult r = new MacTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws AlgorithmInstantiationException, AlgorithmRunException {
        try {
            Mac md = Mac.getInstance(alias, service.getProvider());
            byte[] b = new byte[]{1, 2, 3};
            Provider provider =  service.getProvider();
            String algorithm = service.getAlgorithm();
            String generatorAlgorithm;

            if (algorithm.contains("PBE")) {
                //cool, the pbe key is not ointerface pbekey, so salt do nto bubble formkey to algorithm:-/
                Key key = KeysNaiveGenerator.getPbeKeyWithSalt();
                //so we need to pass salt and ioterations by param
                PBEParameterSpec parmas = new PBEParameterSpec(new byte[]{1, 2, 3, 4, 5, 6, 7, 8}, 5);
                md.init(key, parmas);
            } else {
                KeyGenerator kg;
                Key key;
                try {
                    generatorAlgorithm = algorithm;
                    if (algorithm.startsWith("SslMac")) {
                        /*
                            Fixes SslMac* (e.g. SslMacMD5) as these do not have
                            keygens, Hmac keygens seem to work there
                        */
                        generatorAlgorithm = algorithm.replace("SslMac", "Hmac");
                    } else if (algorithm.startsWith("HmacSHA512/")) {
                        /*
                            Truncated SHA-512 variants (e.g. HmacSHA512/224)
                        */
                        generatorAlgorithm = "HmacSHA512";
                    }
                    kg = KeysNaiveGenerator.getKeyGenerator(generatorAlgorithm, provider);
                    key = kg.generateKey();
                } catch (NoSuchAlgorithmException e) {
                    // use workaround, when there are no keygens available
                    key = KeysNaiveGenerator.getMacKeyFromTlsKeyMaterial(provider);
                }
                md.init(key);
            }

            md.update(b);
            printResult(md.doFinal());
        } catch (NoSuchAlgorithmException ex) {
            throw new AlgorithmInstantiationException(ex);
        } catch (InvalidKeyException | InvalidKeySpecException | InvalidAlgorithmParameterException ex) {
            throw new AlgorithmRunException(ex);
        }

    }

    @Override
    public String getTestedPart() {
        return "Mac";
    }

}
