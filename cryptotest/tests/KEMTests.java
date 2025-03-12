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

    public static byte[] encapsulated_encapsulation(Object e) throws Exception {
        Class c = Class.forName("javax.crypto.KEM$Encapsulated");
        Method m = c.getDeclaredMethod("encapsulation");
        return (byte[]) m.invoke(e);
    }

    public static SecretKey encapsulated_key(Object e) throws Exception {
        Class c = Class.forName("javax.crypto.KEM$Encapsulated");
        Method m = c.getDeclaredMethod("key");
        return (SecretKey) m.invoke(e);
    }

    public static SecretKey decapsulator_decapsulate(Object d, Object o) throws Exception {
        Class c = Class.forName("javax.crypto.KEM$Decapsulator");
        Method m = c.getDeclaredMethod("decapsulate", byte[].class);
        return (SecretKey) m.invoke(d, o);
    }

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws AlgorithmInstantiationException, AlgorithmRunException {
        try {
            Object kem = kem_getInstance(alias, service.getProvider());
            KeyPairGenerator kpg = null;
            if (service.getAlgorithm().equals("DHKEM")) {
                kpg = KeysNaiveGenerator.getKeyPairGenerator("X25519", service.getProvider());
            } else if (service.getAlgorithm().startsWith("ML-")) {
                kpg = KeysNaiveGenerator.getKeyPairGenerator(service.getAlgorithm(), service.getProvider());
            } else {
                throw new RuntimeException("Unsupported KEM algorithm: " + service.getAlgorithm());
            }
            KeyPair kp = kpg.generateKeyPair();
            Object sender = kem_newEncapsulator(kem, kp.getPublic());
            Object encapsulated = encapsulator_encapsulate(sender);
            byte[] encapsulation = encapsulated_encapsulation(encapsulated);
            SecretKey k1 = encapsulated_key(encapsulated);

            Object receiver = kem_newDecapsulator(kem, kp.getPrivate());
            SecretKey k2 = decapsulator_decapsulate(receiver, encapsulation);

            if (!Arrays.equals(k1.getEncoded(), k2.getEncoded())) {
                throw new Exception("Keys are not equal");
            }

            /*
            Code above uses reflection, so that it is buildable on all jdks,
            It is equivalent to following code:

            KEM kem = KEM.getInstance(alias, service.getProvider());
            KeyPairGenerator kpg = null;
            ... per algorithm key generator selection here ...
            KeyPair kp = kpg.generateKeyPair();
            KEM.Encapsulator sender = kem.newEncapsulator(kp.getPublic());
            KEM.Encapsulated encapsulated = sender.encapsulate();
            byte[] encapsulation = encapsulated.encapsulation();
            SecretKey k1 = encapsulated.key();
            KEM.Decapsulator receiver = kem.newDecapsulator(kp.getPrivate());
            SecretKey k2 = receiver.decapsulate(encapsulation);
            if (!Arrays.equals(k1.getEncoded(), k2.getEncoded())) {
                throw new Exception("Keys are not equal");
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
