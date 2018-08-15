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

import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.KeysNaiveGenerator;
import cryptotest.utils.TestResult;

import java.security.*;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import sun.security.internal.spec.TlsKeyMaterialParameterSpec;
import sun.security.internal.spec.TlsMasterSecretParameterSpec;
import sun.security.internal.spec.TlsPrfParameterSpec;
import sun.security.internal.spec.TlsRsaPremasterSecretParameterSpec;

/*
 * IwishThisCouldBeAtTest
 */
public class KeyGeneratorTests extends AlgorithmTest {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        TestResult r = new KeyGeneratorTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    //should be almighty ssl3
    int P_MAJ = 3;
    int P_MIN = 0;

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws AlgorithmInstantiationException, AlgorithmRunException {
        try {
            KeyGenerator kg = KeyGenerator.getInstance(alias, service.getProvider());
            int keyLength = 256;
            SecretKey result = null;
            if (service.getAlgorithm().contains("DESede")) {
                keyLength = 112;
            } else if (service.getAlgorithm().contains("DES")) {
                keyLength = 56;
            }
            //fixme replace all deprecated calls by correct instantiations
            //fixme repalce hardcoded versions by iterating over all version (can be hard by various versions not supported in various impls)
            if (service.getAlgorithm().contains("TlsPrf") || service.getAlgorithm().contains("Tls12Prf")) {
                SecretKey key = KeysNaiveGenerator.getTlsRsaPremasterSecret(P_MAJ, P_MIN);
                TlsPrfParameterSpec params = new TlsPrfParameterSpec(key, "SomeLabel", new byte[]{1, 2, 3}, 10, "sha1", 20, 64);
                kg.init(params);
            } else if (service.getAlgorithm().contains("TlsMasterSecret")) {
                SecretKey key = KeysNaiveGenerator.getTlsRsaPremasterSecret(P_MAJ, P_MIN);
                TlsMasterSecretParameterSpec params = new TlsMasterSecretParameterSpec(key, P_MAJ, P_MIN, new byte[]{1, 2, 3}, new byte[]{1, 2, 3}, "sha1", 16, 64);
                kg.init(params);
            } else if (service.getAlgorithm().contains("TlsKeyMaterial")) {
                SecretKey key = KeysNaiveGenerator.getTlsMasterSecret();
                TlsKeyMaterialParameterSpec params = new TlsKeyMaterialParameterSpec(key, P_MAJ, P_MIN, new byte[]{1, 2, 3}, new byte[]{1, 2, 3},
                        "TlsMasterSecret", 4, 4, 4, 4, "md5", 4, 4);
                kg.init(params);
            } else if (service.getAlgorithm().contains("TlsRsaPremaster")) {
                kg.init(new TlsRsaPremasterSecretParameterSpec(1, 1));
            } else {
                //simple init
                kg.init(keyLength);
            }
            result = kg.generateKey();
            if (result == null) {
                throw new UnsupportedOperationException("Generated key is null for " + service.getAlgorithm() + " in" + service.getProvider().getName());
            }
            printResult(result.getEncoded());
        } catch (NoSuchAlgorithmException ex) {
            throw new AlgorithmInstantiationException(ex);
        } catch (UnsupportedOperationException | InvalidParameterException | ProviderException | InvalidAlgorithmParameterException ex) {
            throw new AlgorithmRunException(ex);
        }

    }

    @Override
    public String getTestedPart() {
        return "KeyGenerator";
    }

}
