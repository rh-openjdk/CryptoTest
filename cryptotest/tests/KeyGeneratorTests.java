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
 * @bug 1422738
 * @library /
 * @build cryptotest.tests.KeyGeneratorTests
 *        cryptotest.Settings
 *        cryptotest.utils.AlgorithmInstantiationException
 *        cryptotest.utils.AlgorithmRunException
 *        cryptotest.utils.AlgorithmTest
 *        cryptotest.utils.KeysNaiveGenerator
 *        cryptotest.utils.TestResult
 * @run main/othervm cryptotest.tests.KeyGeneratorTests
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
