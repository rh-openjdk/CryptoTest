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
 * @build cryptotest.tests.KeyFactoryTests
 *        cryptotest.Settings
 *        cryptotest.utils.AlgorithmIgnoredException
 *        cryptotest.utils.AlgorithmInstantiationException
 *        cryptotest.utils.AlgorithmRunException
 *        cryptotest.utils.AlgorithmTest
 *        cryptotest.utils.KeysNaiveGenerator
 *        cryptotest.utils.TestResult
 * @run main/othervm cryptotest.tests.KeyFactoryTests
 */


package cryptotest.tests;

import cryptotest.utils.AlgorithmIgnoredException;
import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.KeysNaiveGenerator;
import cryptotest.utils.TestResult;
import cryptotest.utils.Misc;

import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAMultiPrimePrivateCrtKey;
import java.security.spec.*;

import static java.math.BigInteger.ONE;

public class KeyFactoryTests extends AlgorithmTest {

    public static void main(String[] args) {
        TestResult r = new KeyFactoryTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws AlgorithmInstantiationException,
            AlgorithmRunException {
        try {
            Provider p = service.getProvider();
            boolean pkcs11fips = Misc.isPkcs11Fips(p);
            KeyFactory keyFactory = KeyFactory.getInstance(alias, p);
            KeySpec privateKeySpec = null;
            KeySpec publicKeySpec = null;
            Key translated = null;

            if (!pkcs11fips && Misc.pkcs11FipsPresent()) {
                // In FIPS setup KeyFactories from other providers
                // are only present for limited internal use,
                // keygens for these are not available -> skip
                throw new AlgorithmIgnoredException();
            }
            if (service.getAlgorithm().equals("HSS/LMS")) {
                // no key generators available for HSS/LMS
                throw new AlgorithmIgnoredException();
            }

            if (service.getAlgorithm().equals("Ed25519") || service.getAlgorithm().equals("EdDSA") || service.getAlgorithm().equals("Ed448")) {
                KeyPairGenerator kpg = KeysNaiveGenerator.getKeyPairGenerator(service.getAlgorithm(), p);
                KeyPair kp = kpg.generateKeyPair();
                translated = keyFactory.translateKey(kp.getPublic());
                if (!pkcs11fips) {
                    // pkcs11 provider in FIPS mode cannot obtain RAW keys
                    // reflection used so it would compile on old jdks
                    Class privateKeyClass = Class.forName("java.security.spec.EdECPrivateKeySpec");
                    Class publicKeyClass = Class.forName("java.security.spec.EdECPublicKeySpec");
                    privateKeySpec = keyFactory.getKeySpec(kp.getPrivate(), privateKeyClass);
                    publicKeySpec = keyFactory.getKeySpec(kp.getPublic(), publicKeyClass);
                }
            } else if (service.getAlgorithm().contains("DSA") && !service.getAlgorithm().startsWith("ML-")) {
                KeyPair kp = KeysNaiveGenerator.getDsaKeyPair(p);
                translated = keyFactory.translateKey(kp.getPublic());
                if (!pkcs11fips) {
                    // pkcs11 provider in FIPS mode cannot obtain RAW keys
                    privateKeySpec = keyFactory.getKeySpec(kp.getPrivate(), DSAPrivateKeySpec.class);
                    publicKeySpec = keyFactory.getKeySpec(kp.getPublic(), DSAPublicKeySpec.class);
                }
            } else if (service.getAlgorithm().contains("RSASSA-PSS")) {
                KeyPairGenerator kpg = KeysNaiveGenerator.getKeyPairGenerator("RSASSA-PSS", p);
                KeyPair kp = kpg.generateKeyPair();
                translated = keyFactory.translateKey(kp.getPublic());
                if (!pkcs11fips) {
                    // pkcs11 provider in FIPS mode cannot obtain RAW keys
                    privateKeySpec = keyFactory.getKeySpec(kp.getPrivate(), RSAPrivateKeySpec.class);
                    publicKeySpec = keyFactory.getKeySpec(kp.getPublic(), RSAPublicKeySpec.class);
                }
            } else if (service.getAlgorithm().contains("X25519")) {
                KeyPairGenerator kpg = KeysNaiveGenerator.getKeyPairGenerator("X25519", p);
                KeyPair kp = kpg.generateKeyPair();
                translated = keyFactory.translateKey(kp.getPublic());
                if (!pkcs11fips) {
                    // pkcs11 provider in FIPS mode cannot obtain RAW keys
                    privateKeySpec = keyFactory.getKeySpec(kp.getPrivate(), PKCS8EncodedKeySpec.class);
                    publicKeySpec = keyFactory.getKeySpec(kp.getPublic(), X509EncodedKeySpec.class);
                }
            } else if (service.getAlgorithm().contains("X448")) {
                KeyPairGenerator kpg = KeysNaiveGenerator.getKeyPairGenerator("X448", p);
                KeyPair kp = kpg.generateKeyPair();
                translated = keyFactory.translateKey(kp.getPublic());
                if (!pkcs11fips) {
                    // pkcs11 provider in FIPS mode cannot obtain RAW keys
                    privateKeySpec = keyFactory.getKeySpec(kp.getPrivate(), PKCS8EncodedKeySpec.class);
                    publicKeySpec = keyFactory.getKeySpec(kp.getPublic(), X509EncodedKeySpec.class);
                }
            } else if (service.getAlgorithm().contains("XDH")) {
                KeyPairGenerator kpg = KeysNaiveGenerator.getKeyPairGenerator("XDH", p);
                KeyPair kp = kpg.generateKeyPair();
                translated = keyFactory.translateKey(kp.getPublic());
                if (!pkcs11fips) {
                    // pkcs11 provider in FIPS mode cannot obtain RAW keys
                    privateKeySpec = keyFactory.getKeySpec(kp.getPrivate(), PKCS8EncodedKeySpec.class);
                    publicKeySpec = keyFactory.getKeySpec(kp.getPublic(), X509EncodedKeySpec.class);
                }
            } else if (service.getAlgorithm().startsWith("ML-")) {
                KeyPairGenerator kpg = KeysNaiveGenerator.getKeyPairGenerator(service.getAlgorithm(), p);
                KeyPair kp = kpg.generateKeyPair();
                translated = keyFactory.translateKey(kp.getPublic());
		if (!pkcs11fips) {
                    // pkcs11 provider in FIPS mode cannot obtain RAW keys
                    privateKeySpec = keyFactory.getKeySpec(kp.getPrivate(), PKCS8EncodedKeySpec.class);
                    publicKeySpec = keyFactory.getKeySpec(kp.getPublic(), X509EncodedKeySpec.class);
                }
            } else if (service.getAlgorithm().contains("RSA")) {
                KeyPair kp = KeysNaiveGenerator.getRsaKeyPair(p);
                translated = keyFactory.translateKey(kp.getPublic());
                if (!pkcs11fips) {
                    // pkcs11 provider in FIPS mode cannot obtain RAW keys
                    privateKeySpec = keyFactory.getKeySpec(kp.getPrivate(), RSAPrivateKeySpec.class);
                    publicKeySpec = keyFactory.getKeySpec(kp.getPublic(), RSAPublicKeySpec.class);
                }
            } else if (service.getAlgorithm().contains("EC")) {
                KeyPair keyPair = KeysNaiveGenerator.getKeyPairGenerator("EC", p).genKeyPair();
                translated = keyFactory.translateKey(keyPair.getPublic());
                if (p.getName().equals("SunEC")) {
                    // These classes are specific to SunEC provider
                    ECPrivateKey ecPrivateKey = ((ECPrivateKey) keyPair.getPrivate());
                    ECPublicKey ecPublicKey = ((ECPublicKey) keyPair.getPublic());
                    privateKeySpec = new ECPrivateKeySpec(ONE, ecPrivateKey.getParams());
                    publicKeySpec = new ECPublicKeySpec(ecPublicKey.getW(), ecPublicKey.getParams());
                }
            } else if (service.getAlgorithm().contains("DiffieHellman") || service.getAlgorithm().contains("DH")) {
                KeyPair kp = KeysNaiveGenerator.getKeyPairGenerator("DiffieHellman", p).genKeyPair();
                translated = keyFactory.translateKey(kp.getPublic());
                if (!pkcs11fips) {
                    // pkcs11 provider in FIPS mode cannot obtain RAW keys
                    privateKeySpec = keyFactory.getKeySpec(kp.getPrivate(), DHPrivateKeySpec.class);
                    publicKeySpec = keyFactory.getKeySpec(kp.getPublic(), DHPublicKeySpec.class);
                }
            } else if (service.getAlgorithm().contains("DES")) {
                privateKeySpec = new DESKeySpec(new byte[]{1, 2, 3, 4, 5, 6, 7});
                publicKeySpec = new DESKeySpec(new byte[]{1, 2, 3, 4, 5, 6, 7});
                translated = keyFactory.translateKey(KeysNaiveGenerator.getDesKey(p));
            }
            if (translated == null) {
                throw new UnsupportedOperationException("Tranlated key is null for " + service.getAlgorithm() + " in"
                        + service.getProvider().getName());
            }
            /*
                this check is skipped for pkcs11 provider in FIPS mode,
                because we cannot obtain KeySpecs (RAW keys) there
            */
            if (!pkcs11fips && (keyFactory.generatePrivate(privateKeySpec) == null || keyFactory.generatePublic(publicKeySpec) ==
                    null)) {
                throw new UnsupportedOperationException("Generated key is null for " + service.getAlgorithm() + " in"
                        + service.getProvider().getName());
            }
        } catch (NoSuchAlgorithmException | ClassNotFoundException e) {
            throw new AlgorithmInstantiationException(e);
        } catch (UnsupportedOperationException | InvalidKeySpecException | InvalidKeyException e) {
            throw new AlgorithmRunException(e);
        }
    }
}
