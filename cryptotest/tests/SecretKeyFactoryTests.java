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
import cryptotest.utils.TestResult;
import cryptotest.utils.KeysNaiveGenerator;
import cryptotest.utils.Misc;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Random;

public class SecretKeyFactoryTests extends AlgorithmTest {
    private Random random = new SecureRandom(new byte[]{6, 6, 6});

    public static void main(String[] args) {
        TestResult r = new SecretKeyFactoryTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws AlgorithmInstantiationException,
            AlgorithmRunException {
        try {
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(alias, service.getProvider());
            KeySpec keySpec;
            SecretKey secretKey;
            Provider p = service.getProvider();
            boolean pkcs11fips = Misc.isPkcs11Fips(p);

            // order of conditions is important!
            if (service.getAlgorithm().contains("PBE")) {
                keySpec = new PBEKeySpec(new char[]{'h', 'e', 's', 'l', 'o'});
            } else if (service.getAlgorithm().contains("DESede")) {
                keySpec = new DESedeKeySpec(generateBytes(24));
            } else if (service.getAlgorithm().contains("DES")) {
                keySpec = new DESKeySpec(generateBytes(8));
            } else if (service.getAlgorithm().contains("PBKDF2")) {
                keySpec = new PBEKeySpec(new char[]{'h', 'e', 's', 'l', 'o'}, generateBytes(8), 1, 1);
            } else if (service.getAlgorithm().contains("AES")) {
                keySpec = new SecretKeySpec(generateBytes(16), service.getAlgorithm());
            } else if (service.getAlgorithm().contains("ARCFOUR")) {
                keySpec = new SecretKeySpec(generateBytes(8), service.getAlgorithm());
            } else  {
                keySpec = null;
            }

            if (!pkcs11fips
              || service.getAlgorithm().contains("PBE")
              || service.getAlgorithm().contains("PBKDF2")) {
                secretKey = secretKeyFactory.generateSecret(keySpec);
            } else {
                /* pkcs11 provider in fips mode does not support raw secrets ala *Spec */
                secretKey = KeysNaiveGenerator.getKeyGenerator(service.getAlgorithm(), p).generateKey();
            }

            if (secretKey == null || secretKeyFactory.translateKey(secretKey) == null) {
                throw new UnsupportedOperationException("Generated key is null for " + service.getAlgorithm() + " in"
                        + service.getProvider().getName());
            }
        } catch (NoSuchAlgorithmException e) {
            throw new AlgorithmInstantiationException(e);
        } catch (UnsupportedOperationException | InvalidKeySpecException | InvalidKeyException e) {
            throw new AlgorithmRunException(e);
        }
    }

    private byte[] generateBytes(int length) {
        byte[] key = new byte[length];
        random.nextBytes(key);
        return key;
    }
}
