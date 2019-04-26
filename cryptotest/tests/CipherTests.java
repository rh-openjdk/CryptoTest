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
package cryptotest.tests;

import cryptotest.Settings;
import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.TestResult;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
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

    private static final Map<String, Byte> blockLengthMap;

    static {
        blockLengthMap = new HashMap<>();
        blockLengthMap.put("DES", (byte) 8);
        blockLengthMap.put("DESede", (byte) 8);
    }

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
            byte[] b;
            if (isPadding(service.getAlgorithm()) || isPadding(alias)) {
                // If we use no padding, input length has to be equal to the
                // cipher block length.
                b = generateBlock(getPaddingLength(service.getAlgorithm(), alias));
            } else {
                b = new byte[]{1, 2, 3};
            }
            Key key = null;
            if (service.getAlgorithm().contains("RSA")) {
                key = getRsaPrivateKey();
            } else if (service.getAlgorithm().contains("PBE")) {
                key = getPbeKey();
            } else if (service.getAlgorithm().contains("DESede")) {
                key = getDesedeKey();
            } else if (service.getAlgorithm().contains("DES")) {
                key = getDesKey();
            } else if (service.getAlgorithm().contains("Blowfish")) {
                key = getBlowfishKey();
            } else if (service.getAlgorithm().contains("AES_192")
                    || service.getAlgorithm().contains("AESWrap_192")) {
                b = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
                key = getAesKey192();
            } else if (service.getAlgorithm().contains("AES_256")
                    || service.getAlgorithm().contains("AESWrap_256")) {
                b = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
                key = getAesKey256();
            } else if (service.getAlgorithm().contains("AES")) {
                b = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
                key = getAesKey();
            } else if (service.getAlgorithm().contains("RC2")) {
                b = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
                key = getRc2Key();
            } else if (service.getAlgorithm().contains("ARCFOUR")) {
                b = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
                key = getArcFourKey();
            } else if (service.getAlgorithm().contains("ChaCha20")) {
                AlgorithmParameterSpec params = new IvParameterSpec(new byte[]{1,2,3,4,5,6,7,8,9,10,11,12});
                KeyGenerator.getInstance("ChaCha20").init(params);
                key = KeyGenerator.getInstance("ChaCha20").generateKey();
            }

            if (service.getAlgorithm().toLowerCase().contains("wrap")) {
                c.init(Cipher.WRAP_MODE, key);
                AlgorithmTest.printResult(c.wrap(key));
            } else {
                c.init(Cipher.ENCRYPT_MODE, key);
                if (!isNss(service.getProvider(), service) || Settings.runNss) {
                    AlgorithmTest.printResult(c.doFinal(b));
                    if (!service.getAlgorithm().contains("AES")) {
                        AlgorithmTest.printResult(c.doFinal());
                    }
                }
            }
        } catch(NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException| InvalidKeySpecException ex){
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

    private boolean isNss(Provider provider, Provider.Service service) {
        //ignoring some broken nssnss:
        return provider.getName().endsWith("-NSS")
                && (service.getAlgorithm().equals("DESede/CBC/NoPadding")
                || service.getAlgorithm().equals("DESede/CBC/PKCS5Padding")
                || service.getAlgorithm().equals("DESede/ECB/NoPadding")
                || service.getAlgorithm().equals("DESede/ECB/PKCS5Padding")
                || service.getAlgorithm().equals("DES/ECB/NoPadding")
                || service.getAlgorithm().equals("DES/ECB/PKCS5Padding")
                || service.getAlgorithm().equals("DES/CBC/NoPadding")
                || service.getAlgorithm().equals("AES/CBC/PKCS5Padding")
                || service.getAlgorithm().equals("AES/CBC/NoPadding")
                || service.getAlgorithm().equals("DES/CBC/PKCS5Padding")
                || service.getAlgorithm().equals("AES/CTR/NoPadding")
                || service.getAlgorithm().equals("AES_128/ECB/NoPadding")
                || service.getAlgorithm().equals("AES_192/ECB/NoPadding")
                || service.getAlgorithm().equals("AES_256/CBC/NoPadding"));
    }

    private static byte[] generateBlock(byte blockLength) {
        byte[] block = new byte[blockLength];
        for (byte i = 0; i < blockLength; i++) {
            //block[i] = i + 1;
            block[i] = 1;
        }
        return block;
    }

    private byte getPaddingLength(String name, String alias) {
        String[] aliasComponents = splitNssName(name);
        Byte b = blockLengthMap.get(aliasComponents[0]);
        if (b == null) {
            aliasComponents = splitNssName(alias);
            b = blockLengthMap.get(aliasComponents[0]);

        }
        return b;

    }

    private boolean isPadding(String s) {
        final String[] aliasComponents = splitNssName(s);
        return (aliasComponents.length == 3
                && blockLengthMap.containsKey(aliasComponents[0])
                && aliasComponents[2].equals("NoPadding"));
    }

    private String[] splitNssName(String s) {
        return s.split("/");
    }

}
