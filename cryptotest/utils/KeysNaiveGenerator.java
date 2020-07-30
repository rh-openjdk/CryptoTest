/*   Copyright (C) 2017 Red Hat, Inc.

 This file is part of IcedTea.

 IcedTea is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License as published by
 the Free Software Foundation, version 2.

 IcedTea is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with IcedTea; see the file COPYING.  If not, write to
 the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 02110-1301 USA.

 Linking this library statically or dynamically with other modules is
 making a combined work based on this library.  Thus, the terms and
 conditions of the GNU General Public License cover the whole
 combination.

 As a special exception, the copyright holders of this library give you
 permission to link this library with independent modules to produce an
 executable, regardless of the license terms of these independent
 modules, and to copy and distribute the resulting executable under
 terms of your choice, provided that you also meet, for each linked
 independent module, the terms and conditions of the license of that
 module.  An independent module is a module which is not derived from
 or based on this library.  If you modify this library, you may extend
 this exception to your version of the library, but you are not
 obligated to do so.  If you do not wish to do so, delete this
 exception statement from your version.
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

    public static SecretKey getTlsMasterSecret() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
//        KeyGenerator kg = KeyGenerator.getInstance("TlsMasterSecret");
//        kg.init(new TlsRsaPremasterSecretParameterSpec(version.major, version.minor));
//        return kg.generateKey();
        SecretKey masterkey = new SecretKeySpec(new byte[]{1, 2, 3}, "TlsMasterSecret");
        return masterkey;

    }

    public static SecretKey getTlsRsaPremasterSecret(int major, int minor) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        KeyGenerator kg = KeyGenerator.getInstance("SunTlsRsaPremasterSecret");
        kg.init(new TlsRsaPremasterSecretParameterSpec(major, minor));
        return kg.generateKey();
    }

    public static SecretKey getTlsRsaPremasterSecretProtocolVersion(/*private since jdk11 ProtocolVersion*/Object version) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        KeyGenerator kg = KeyGenerator.getInstance("SunTlsRsaPremasterSecret");
        int major = getIntValueFromHiddenObjectCatched(version, "major");
        int minor = getIntValueFromHiddenObjectCatched(version, "minor");
        kg.init(new TlsRsaPremasterSecretParameterSpec(major, minor));
        return kg.generateKey();
    }

    private static int getIntValueFromHiddenObjectCatched(Object version, String field) throws RuntimeException {
        try {
            return getIntValueFromHiddenObject(version, field);
        } catch (IllegalArgumentException | NoSuchFieldException | IllegalAccessException | SecurityException ex) {
            throw new RuntimeException(ex);
        }
    }

    private static int getIntValueFromHiddenObject(Object version, String field) throws IllegalArgumentException, NoSuchFieldException, IllegalAccessException, SecurityException {
        Field major = version.getClass().getDeclaredField(field);
        major.setAccessible(true);
        int majorValue = (int) major.get(version);
        return majorValue;
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
