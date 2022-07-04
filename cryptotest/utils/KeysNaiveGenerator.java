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

package cryptotest.utils;

import java.lang.reflect.Field;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import sun.security.internal.spec.TlsRsaPremasterSecretParameterSpec;
import sun.security.internal.spec.TlsMasterSecretParameterSpec;
import sun.security.internal.spec.TlsKeyMaterialParameterSpec;
import sun.security.internal.spec.TlsPrfParameterSpec;
import sun.security.internal.spec.TlsKeyMaterialSpec;

public class KeysNaiveGenerator {

    public static KeyGenerator getKeyGenerator(String name, Provider provider) throws NoSuchAlgorithmException {
        KeyGenerator kg;
        try {
            kg = KeyGenerator.getInstance(name, provider);
        } catch (NoSuchAlgorithmException e) {
            kg = KeyGenerator.getInstance(name);
        }
        return kg;
    }

    public static KeyPairGenerator getKeyPairGenerator(String name, Provider provider) throws NoSuchAlgorithmException {
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance(name, provider);
        } catch (NoSuchAlgorithmException e) {
            kpg = KeyPairGenerator.getInstance(name);
        }
        return kpg;
    }

    public static Key getDesKey(Provider provider) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = getKeyGenerator("DES", provider);
        keyGenerator.init(56);
        return keyGenerator.generateKey();
    }

    // https://hg.openjdk.java.net/jdk8u/jdk8u/jdk/file/4687075d8ccf/src/share/classes/sun/security/internal/spec/
    public static TlsRsaPremasterSecretParameterSpec getTlsPremasterParam(int major, int minor) {
        // https://hg.openjdk.java.net/jdk8u/jdk8u/jdk/file/4687075d8ccf/src/share/classes/sun/security/ssl/RSAClientKeyExchange.java#l79
        int version = major << 8 | minor;
        return new TlsRsaPremasterSecretParameterSpec(version, version);
    }

    public static TlsMasterSecretParameterSpec getTlsMasterParam(Provider provider, int major, int minor) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        SecretKey premasterKey = getTlsRsaPremasterSecret(provider, major, minor);
        TlsMasterSecretParameterSpec params =
            new TlsMasterSecretParameterSpec(
                premasterKey, major, minor,
                new byte[32], new byte[32], "SHA-256", 32, 64);
        return params;
    }

    public static TlsKeyMaterialParameterSpec getTlsKeyMaterialParam(Provider provider, int major, int minor) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        SecretKey masterSecret = getTlsMasterSecret(provider, major, minor);
        // http://hg.openjdk.java.net/jdk-updates/jdk11u/file/db89b5b9b98b/src/java.base/share/classes/sun/security/ssl/SSLTrafficKeyDerivation.java#l274
        // TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
        // http://hg.openjdk.java.net/jdk-updates/jdk11u/file/db89b5b9b98b/src/java.base/share/classes/sun/security/ssl/CipherSuite.java#l163
        TlsKeyMaterialParameterSpec params = new TlsKeyMaterialParameterSpec(
            masterSecret, major, minor,
            new byte[32],
            new byte[32],
            // http://hg.openjdk.java.net/jdk-updates/jdk11u/file/db89b5b9b98b/src/java.base/share/classes/sun/security/ssl/SSLCipher.java#l243
            // cipher.algorithm, cipher.keySize, cipher.expandedSize
            "AES", 32, 32,
            // ivSize, macAlg.size
            0 /*12*/, 32,
            // http://hg.openjdk.java.net/jdk8/jdk8/jdk/file/931fb59eae26/src/share/classes/sun/security/ssl/CipherSuite.java#l628
            // hash.name, hash.length, hash.blocksize
            "SHA-256", 32, 64);
        return params;
    }

    public static TlsPrfParameterSpec getTlsPrfParam(Provider provider, int major, int minor) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        SecretKey masterSecret = getTlsMasterSecret(provider, major, minor);
        TlsPrfParameterSpec params = new TlsPrfParameterSpec(
            masterSecret,
            "client finished", "a".getBytes(), 12,
            "SHA-256", 32, 64);
        return params;
    }

    public static SecretKey getTlsRsaPremasterSecret(Provider provider, int major, int minor) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        KeyGenerator kg = getKeyGenerator("SunTlsRsaPremasterSecret", provider);
        kg.init(getTlsPremasterParam(major, minor));
        return kg.generateKey();
    }

    public static SecretKey getTlsMasterSecret(Provider provider, int major, int minor) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        KeyGenerator kg = getKeyGenerator("SunTls12MasterSecret", provider);
        kg.init(getTlsMasterParam(provider, major, minor));
        return kg.generateKey();
    }

    // Complicated way to obtain Mac key when there are no Mac key generators available (FIPS mode)
    public static Key getMacKeyFromTlsKeyMaterial(Provider provider) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        KeyGenerator kg = getKeyGenerator("SunTls12KeyMaterial", provider);
        kg.init(getTlsKeyMaterialParam(provider, 3, 3));
        Key key = kg.generateKey();
        if (key instanceof TlsKeyMaterialSpec) {
            return ((TlsKeyMaterialSpec) key).getClientMacKey();
        }
        return null;
    }

    public static SecretKey getPbeKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec keySpec = new PBEKeySpec(new char[]{'a', 'b'});
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBE");
        SecretKey key = keyFactory.generateSecret(keySpec);
        return key;
    }

    public static SecretKey getPbeKeyWithSalt() throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec keySpec = new PBEKeySpec(new char[]{'a', 'b'}, new byte[]{1, 2}, 5);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBE");
        SecretKey key = keyFactory.generateSecret(keySpec);
        return key;
    }

    public static SecretKey getDesedeKey(Provider provider) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = getKeyGenerator("DESede", provider);
        /* keyGenerator.init(112); */
        return keyGenerator.generateKey();
    }

    public static KeyPair getRsaKeyPair(Provider provider) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = getKeyPairGenerator("RSA", provider);
        return keyGen.genKeyPair();
    }

    public static PrivateKey getRsaPrivateKey(Provider provider) throws NoSuchAlgorithmException {
        return getRsaKeyPair(provider).getPrivate();

    }

    public static KeyPair getDsaKeyPair(Provider provider) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = getKeyPairGenerator("DSA", provider);
        return keyGen.genKeyPair();
    }

    public static PrivateKey getDsaPrivateKey(Provider provider) throws NoSuchAlgorithmException {
        return getDsaKeyPair(provider).getPrivate();
    }

    public static KeyPair getDsaKeyPair1024(Provider provider) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = getKeyPairGenerator("DSA", provider);
        keyGen.initialize(1024);
        return keyGen.genKeyPair();
    }

    public static PrivateKey getDsaPrivateKey1024(Provider provider) throws NoSuchAlgorithmException {
        return getDsaKeyPair1024(provider).getPrivate();
    }

    public static KeyPair getEcKeyPair(Provider provider) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = getKeyPairGenerator("EC", provider);
        return keyGen.genKeyPair();
    }

    public static PrivateKey getEcPrivateKey(Provider provider) throws NoSuchAlgorithmException {
        return getEcKeyPair(provider).getPrivate();

    }

    public static SecretKey getBlowfishKey(Provider provider) throws NoSuchAlgorithmException {
        KeyGenerator kg = getKeyGenerator("Blowfish", provider);
        return kg.generateKey();
    }

    public static SecretKey getRc2Key() {
        String Key = "Something";
        byte[] KeyData = Key.getBytes();
        return new SecretKeySpec(KeyData, "RC2");
    }

    public static SecretKey getArcFourKey(Provider provider) throws NoSuchAlgorithmException {
        KeyGenerator kg = getKeyGenerator("ARCFOUR", provider);
        return kg.generateKey();
    }

    public static SecretKey getAesKey(Provider provider) throws NoSuchAlgorithmException {
        KeyGenerator kg = getKeyGenerator("AES", provider);
        kg.init(128);
        return kg.generateKey();
    }

    public static SecretKey getAesKey192(Provider provider) throws NoSuchAlgorithmException {
        KeyGenerator kg = getKeyGenerator("AES", provider);
        kg.init(192);
        return kg.generateKey();
    }

    public static SecretKey getAesKey256(Provider provider) throws NoSuchAlgorithmException {
        KeyGenerator kg = getKeyGenerator("AES", provider);
        kg.init(256);
        return kg.generateKey();
    }
}
