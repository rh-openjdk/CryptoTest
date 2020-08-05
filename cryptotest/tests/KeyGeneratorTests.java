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

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws AlgorithmInstantiationException, AlgorithmRunException {
        try {
            Provider provider = service.getProvider();
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
            // TLS 1.1: 3, 2
            // TLS 1.2: 3, 3
            if (service.getAlgorithm().contains("SunTlsRsaPremasterSecret")) {
                TlsRsaPremasterSecretParameterSpec params = KeysNaiveGenerator.getTlsPremasterParam(3, 3);
                kg.init(params);
            } else if (service.getAlgorithm().contains("SunTlsMasterSecret")) {
                // SunTlsMasterSecret used for tls < 1.2, SunTls12MasterSecret for tls >= 1.2
                // https://hg.openjdk.java.net/jdk-updates/jdk11u/file/db89b5b9b98b/src/java.base/share/classes/sun/security/ssl/SSLMasterKeyDerivation.java#l99
                TlsMasterSecretParameterSpec params = KeysNaiveGenerator.getTlsMasterParam(provider, 3, 2);
                kg.init(params);
            } else if (service.getAlgorithm().contains("SunTls12MasterSecret")) {
                TlsMasterSecretParameterSpec params = KeysNaiveGenerator.getTlsMasterParam(provider, 3, 3);
                kg.init(params);
            } else if (service.getAlgorithm().contains("SunTlsKeyMaterial")) {
                // SunTlsKeyMaterial used for tls < 1.2, SunTls12KeyMaterial for tls >= 1.2
                // https://hg.openjdk.java.net/jdk-updates/jdk11u/file/db89b5b9b98b/src/java.base/share/classes/sun/security/ssl/SSLTrafficKeyDerivation.java#l236
                TlsKeyMaterialParameterSpec params = KeysNaiveGenerator.getTlsKeyMaterialParam(provider, 3, 2);
                kg.init(params);
            } else if (service.getAlgorithm().contains("SunTls12KeyMaterial")) {
                TlsKeyMaterialParameterSpec params = KeysNaiveGenerator.getTlsKeyMaterialParam(provider, 3, 3);
                kg.init(params);
            } else if (service.getAlgorithm().contains("SunTlsPrf")) {
                // SunTlsPrf is used for tls < 1.2
                // https://hg.openjdk.java.net/jdk-updates/jdk11u/file/db89b5b9b98b/src/java.base/share/classes/sun/security/ssl/Finished.java#l225
                TlsPrfParameterSpec params = KeysNaiveGenerator.getTlsPrfParam(provider, 3, 2);
                kg.init(params);
            } else if (service.getAlgorithm().contains("SunTls12Prf")) {
                // SunTls12Prf is used for tls >= 1.2
                // https://hg.openjdk.java.net/jdk-updates/jdk11u/file/db89b5b9b98b/src/java.base/share/classes/sun/security/ssl/Finished.java#l276
                TlsPrfParameterSpec params = KeysNaiveGenerator.getTlsPrfParam(provider, 3, 3);
                kg.init(params);
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
