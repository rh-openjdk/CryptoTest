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
