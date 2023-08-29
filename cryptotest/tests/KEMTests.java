/*
 * The MIT License
 *
 * Copyright 2023 Red Hat, Inc.
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
 * @requires jdk.version.major >= 21
 * @modules java.base/java.security:open
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
 * @run main/othervm cryptotest.tests.KEMTests
 */

package cryptotest.tests;

import cryptotest.utils.AlgorithmIgnoredException;
import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.KeysNaiveGenerator;
import cryptotest.utils.TestResult;
import java.security.*;
import javax.crypto.*;
import java.lang.reflect.*;
import java.util.Arrays;

public class KEMTests extends AlgorithmTest {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        TestResult r = new KEMTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    public static Object kem_getInstance(String alias, Provider p) throws Exception {
        Class c = Class.forName("javax.crypto.KEM");
        Method m = c.getDeclaredMethod("getInstance", String.class, Provider.class);
        return m.invoke(null, alias, p);
    }

    public static Object kem_newEncapsulator(Object kem, PublicKey key) throws Exception {
        Class c = Class.forName("javax.crypto.KEM");
        Method m = c.getDeclaredMethod("newEncapsulator", PublicKey.class);
        return m.invoke(kem, key);
    }

    public static Object kem_newDecapsulator(Object kem, PrivateKey key) throws Exception {
        Class c = Class.forName("javax.crypto.KEM");
        Method m = c.getDeclaredMethod("newDecapsulator", PrivateKey.class);
        return m.invoke(kem, key);
    }

    public static Object encapsulator_encapsulate(Object e) throws Exception {
        Class c = Class.forName("javax.crypto.KEM$Encapsulator");
        Method m = c.getDeclaredMethod("encapsulate");
        return m.invoke(e);
    }

    public static Object encapsulated_encapsulation(Object e) throws Exception {
        Class c = Class.forName("javax.crypto.KEM$Encapsulated");
        Method m = c.getDeclaredMethod("encapsulation");
        return m.invoke(e);
    }

    public static Object encapsulated_key(Object e) throws Exception {
        Class c = Class.forName("javax.crypto.KEM$Encapsulated");
        Method m = c.getDeclaredMethod("key");
        return m.invoke(e);
    }

    public static Object decapsulator_decapsulate(Object d, Object o) throws Exception {
        Class c = Class.forName("javax.crypto.KEM$Decapsulator");
        Method m = c.getDeclaredMethod("decapsulate", byte[].class);
        return m.invoke(d, o);
    }

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws AlgorithmInstantiationException, AlgorithmRunException {
        try {
            Object kem = kem_getInstance(alias, service.getProvider());
            KeyPairGenerator kpg = null;
            if (service.getAlgorithm().equals("DHKEM")) {
                kpg = KeysNaiveGenerator.getKeyPairGenerator("X25519", service.getProvider());
            } else {
                throw new RuntimeException("Unsupported KEM algorithm: " + service.getAlgorithm());
            }
            KeyPair kp = kpg.generateKeyPair();
            Object sender = kem_newEncapsulator(kem, kp.getPublic());
            Object encapsulated = encapsulator_encapsulate(sender);
            Object encapsulation = encapsulated_encapsulation(encapsulated);
            SecretKey k1 = (SecretKey) encapsulated_key(encapsulated);

            Object receiver = kem_newDecapsulator(kem, kp.getPrivate());
            SecretKey k2 = (SecretKey) decapsulator_decapsulate(receiver, encapsulation);

            if (!Arrays.equals(k1.getEncoded(), k2.getEncoded())) {
                throw new Exception("Keys are not equal");
            }
        } catch (AlgorithmIgnoredException aie) {
            throw aie;
        } catch (NoSuchAlgorithmException ex) {
            throw new AlgorithmInstantiationException(ex);
        } catch (Exception ex) {
            throw new AlgorithmRunException(ex);
        }
    }
}
