/*
 * The MIT License
 *
 * Copyright 2025 Red Hat, Inc.
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
 * @requires jdk.version.major >= 24
 * @modules java.base/java.security:open
 *          java.base/sun.security.internal.spec
 * @bug 6666666
 * @library /
 * @build cryptotest.tests.KEMTests
 *        cryptotest.Settings
 *        cryptotest.utils.AlgorithmIgnoredException
 *        cryptotest.utils.AlgorithmInstantiationException
 *        cryptotest.utils.AlgorithmRunException
 *        cryptotest.utils.AlgorithmTest
 *        cryptotest.utils.KeysNaiveGenerator
 *        cryptotest.utils.TestResult
 * @run main/othervm cryptotest.tests.KDFTests
 */

package cryptotest.tests;

import cryptotest.utils.AlgorithmIgnoredException;
import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.KeysNaiveGenerator;
import cryptotest.utils.TestResult;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.lang.reflect.*;

public class KDFTests extends AlgorithmTest {

    /**
     * @param args the command line arguments
     */

    public static void main(String[] args) {
        TestResult r = new KDFTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    public static Object _KDF_getInstance(String alias, Provider p) throws Exception {
        Class c = Class.forName("javax.crypto.KDF");
        Method m = c.getDeclaredMethod("getInstance", String.class, Provider.class);
        return m.invoke(null, alias, p);
    }

    public static Object _HKDFParameterSpec_ofExtract() throws Exception {
        Class c = Class.forName("javax.crypto.spec.HKDFParameterSpec");
        Method m = c.getDeclaredMethod("ofExtract");
        return m.invoke(null);
    }

    public static Object _Builder_addIKM(Object builder, byte[] ikm) throws Exception {
        Class c = Class.forName("javax.crypto.spec.HKDFParameterSpec$Builder");
        Method m = c.getDeclaredMethod("addIKM", byte[].class);
        return m.invoke(builder, ikm);
    }

    public static Object _Builder_addSalt(Object builder, byte[] salt) throws Exception {
        Class c = Class.forName("javax.crypto.spec.HKDFParameterSpec$Builder");
        Method m = c.getDeclaredMethod("addSalt", byte[].class);
        return m.invoke(builder, salt);
    }

    public static AlgorithmParameterSpec _Builder_thenExpand(Object builder, byte[] info, int size) throws Exception {
        Class c = Class.forName("javax.crypto.spec.HKDFParameterSpec$Builder");
        Method m = c.getDeclaredMethod("thenExpand", byte[].class, int.class);
        return (AlgorithmParameterSpec) m.invoke(builder, info, size);
    }

    public static SecretKey _KDF_deriveKey(Object kdf, String alg, AlgorithmParameterSpec derivationSpec) throws Exception {
        Class c = Class.forName("javax.crypto.KDF");
        Method m = c.getDeclaredMethod("deriveKey", String.class, AlgorithmParameterSpec.class);
        return (SecretKey) m.invoke(kdf, alg, derivationSpec);
    }

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws AlgorithmInstantiationException, AlgorithmRunException {
        try {
            Object kdf = _KDF_getInstance(alias, service.getProvider());
            AlgorithmParameterSpec derivationSpec = null;
            if (service.getAlgorithm().startsWith("HKDF")) {
                Object builder = _HKDFParameterSpec_ofExtract();
                builder = _Builder_addIKM(builder, new byte[]{1,2,3,4,5,6,7,8,9,10});
                builder = _Builder_addSalt(builder, new byte[]{1,2,1,2,1,2,1,2,1,2});
                derivationSpec = _Builder_thenExpand(builder, new byte[]{4,3,2,1}, 32);
            }
            if (derivationSpec == null) {
                throw new Exception("Failed to generate derivationSpec");
            }
            SecretKey sKey = _KDF_deriveKey(kdf, "AES", derivationSpec);
            if (sKey == null) {
                throw new Exception("Failed to generate secret key");
            }

            /*

            Code above uses reflection, so that it is buildable on all jdks,
            It is equivalent to following code:

            KDF kdf = KDF.getInstance(alias, service.getProvider());
            AlgorithmParameterSpec derivationSpec = null;
            if (service.getAlgorithm().startsWith("HKDF")) {
                HKDFParameterSpec.Builder builder = HKDFParameterSpec.ofExtract();
                builder = builder.addIKM(new byte[]{1,2,3,4,5,6,7,8,9,10});
                builder = builder.addSalt(new byte[]{1,2,1,2,1,2,1,2,1,2});
                derivationSpec = builder.thenExpand(new byte[]{4,3,2,1}, 32);
            }
            if (derivationSpec == null) {
                throw new Exception("Failed to generate derivationSpec");
            }
            SecretKey sKey = kdf.deriveKey("AES", derivationSpec);
            if (sKey == null) {
                throw new Exception("Failed to generate secret key");
            }

            */
        } catch (AlgorithmIgnoredException aie) {
            throw aie;
        } catch (NoSuchAlgorithmException ex) {
            throw new AlgorithmInstantiationException(ex);
        } catch (Exception ex) {
            throw new AlgorithmRunException(ex);
        }
    }
}
