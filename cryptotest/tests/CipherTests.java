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
 * @build cryptotest.tests.CipherTests
 *        cryptotest.Settings
 *        cryptotest.utils.AlgorithmInstantiationException
 *        cryptotest.utils.AlgorithmRunException
 *        cryptotest.utils.AlgorithmTest
 *        cryptotest.utils.KeysNaiveGenerator
 *        cryptotest.utils.TestResult
 * @run main/othervm cryptotest.tests.CipherTests
 */

package cryptotest.tests;

import cryptotest.Settings;
import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.TestResult;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

import static cryptotest.utils.KeysNaiveGenerator.*;

/*
 * IwishThisCouldBeAtTest
 */
public class CipherTests extends AlgorithmTest {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        TestResult r = new CipherTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws
            AlgorithmInstantiationException, AlgorithmRunException {
        try {
            Cipher c = Cipher.getInstance(alias, service.getProvider());
            int blockSize = c.getBlockSize();
            byte[] b = generateBlock(blockSize > 0 ? blockSize : 16);

            Key key = null;
            AlgorithmParameterSpec initSpec = null;
            if (service.getAlgorithm().contains("RSA")) {
                key = getRsaPrivateKey(service.getProvider());
            } else if (service.getAlgorithm().contains("PBE")) {
                key = getPbeKey();
            } else if (service.getAlgorithm().contains("DESede")) {
                key = getDesedeKey(service.getProvider());
            } else if (service.getAlgorithm().contains("DES")) {
                key = getDesKey(service.getProvider());
            } else if (service.getAlgorithm().contains("Blowfish")) {
                key = getBlowfishKey(service.getProvider());
            } else if (service.getAlgorithm().contains("AES_192")
                    || service.getAlgorithm().contains("AESWrap_192")) {
                key = getAesKey192(service.getProvider());
            } else if (service.getAlgorithm().contains("AES_256")
                    || service.getAlgorithm().contains("AESWrap_256")) {
                key = getAesKey256(service.getProvider());
            } else if (service.getAlgorithm().contains("AES")) {
                key = getAesKey(service.getProvider());
            } else if (service.getAlgorithm().contains("RC2")) {
                key = getRc2Key();
            } else if (service.getAlgorithm().contains("ARCFOUR")) {
                key = getArcFourKey(service.getProvider());
            } else if (service.getAlgorithm().contains("ChaCha20-Poly1305")) {
                KeyGenerator kg = KeyGenerator.getInstance("ChaCha20");
                b = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
                initSpec = new IvParameterSpec(b);
                kg.init(256);
                key = KeyGenerator.getInstance("ChaCha20").generateKey();

            } else if (service.getAlgorithm().contains("ChaCha20")) {
                KeyGenerator kg = KeyGenerator.getInstance("ChaCha20");
                b = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
                // use reflect api, jdk 8 does not have this class
                Class<?> chacha = Class.forName("javax.crypto.spec.ChaCha20ParameterSpec");
                Constructor chachaConstr = chacha.getConstructor(byte[].class, int.class);
                initSpec = (AlgorithmParameterSpec) chachaConstr.newInstance(b, 10);
                kg.init(256);
                key = KeyGenerator.getInstance("ChaCha20").generateKey();
            }
            if (initSpec != null){
                c.init(Cipher.ENCRYPT_MODE, key, initSpec);
            }
            else if (service.getAlgorithm().toLowerCase().contains("wrap")) {
                c.init(Cipher.WRAP_MODE, key);
                AlgorithmTest.printResult(c.wrap(key));
            } else {
                c.init(Cipher.ENCRYPT_MODE, key);
                AlgorithmTest.printResult(c.doFinal(b));
            }
        } catch(NoSuchAlgorithmException | ClassNotFoundException | NoSuchMethodException | NoSuchPaddingException | InvalidKeySpecException | InvalidAlgorithmParameterException | InstantiationException | IllegalAccessException | InvocationTargetException | NullPointerException ex){
            throw new AlgorithmInstantiationException(ex);
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException |
                UnsupportedOperationException | InvalidParameterException | ProviderException ex) {
            throw new AlgorithmRunException(ex);
        }

    }

    @Override
    public String getTestedPart() {
        return "Cipher";
    }

    private static byte[] generateBlock(int blockLength) {
        byte[] block = new byte[blockLength];
        for (int i = 0; i < blockLength; i++) {
            //block[i] = i + 1;
            block[i] = 1;
        }
        return block;
    }
}
