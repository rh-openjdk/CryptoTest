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

package cryptotest.tests;

import cryptotest.Settings;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.ClassFinder;
import cryptotest.utils.Misc;
import cryptotest.utils.TestResult;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/*
 * WARNING build path must be regenerated with each test added:(
 * 
 * @test
 * @modules java.base/java.security:open
 *          java.base/com.sun.crypto.provider
 *          java.base/sun.security.internal.spec
 *          java.base/sun.security.ssl
 *          java.base/sun.security.x509
 *          java.security.jgss/sun.security.jgss
 *          java.security.jgss/sun.security.jgss.krb5
 *          java.security.jgss/sun.security.krb5
 *          java.smartcardio/javax.smartcardio
 *          java.xml.crypto/org.jcp.xml.dsig.internal.dom
 *          jdk.crypto.ec/sun.security.ec
 * @bug 6666666
 * @library /
 * @build cryptotest.CryptoTest
 *        cryptotest.Settings
 *        cryptotest.tests.AlgorithmParameterGeneratorTests
 *        cryptotest.tests.AlgorithmParametersTests
 *        cryptotest.tests.CertificateFactoryTests
 *        cryptotest.tests.CertPathBuilderTests
 *        cryptotest.tests.CertPathValidatorTests
 *        cryptotest.tests.CertStoreTests
 *        cryptotest.tests.CipherTests
 *        cryptotest.tests.ConfigurationTests
 *        cryptotest.tests.GssApiMechanismTests
 *        cryptotest.tests.KEMTests
 *        cryptotest.tests.KeyAgreementTests
 *        cryptotest.tests.KeyFactoryTests
 *        cryptotest.tests.KeyGeneratorTests
 *        cryptotest.tests.KeyInfoFactoryTests
 *        cryptotest.tests.KeyManagerFactoryTests
 *        cryptotest.tests.KeyPairGeneratorTests
 *        cryptotest.tests.KeyStoreTests
 *        cryptotest.tests.MacTests
 *        cryptotest.tests.MessageDigestTests
 *        cryptotest.tests.PolicyTests
 *        cryptotest.tests.SaslClientFactoryTests
 *        cryptotest.tests.SaslServerFactoryTests
 *        cryptotest.tests.SecretKeyFactoryTests
 *        cryptotest.tests.SecureRandomTests
 *        cryptotest.tests.SignatureTests
 *        cryptotest.tests.SSLContextTests
 *        cryptotest.tests.TerminalFactoryTests
 *        cryptotest.tests.TestProviders
 *        cryptotest.tests.TestServices
 *        cryptotest.tests.TransformServiceTests
 *        cryptotest.tests.TrustManagerFactoryTests
 *        cryptotest.tests.XMLSignatureFactoryTest
 *        cryptotest.utils.AlgorithmInstantiationException
 *        cryptotest.utils.AlgorithmRunException
 *        cryptotest.utils.AlgorithmTest
 *        cryptotest.utils.ClassFinder
 *        cryptotest.utils.KeysNaiveGenerator
 *        cryptotest.utils.Misc
 *        cryptotest.utils.TestResult
 *        cryptotest.utils.Xml
 * @run main/othervm/timeout=240 cryptotest.tests.TestServices
 */
public class TestServices {

    private static String[] mustBeCurves = new String[]{};
    //eg https://bugzilla.redhat.com/show_bug.cgi?id=1422738#c10
    private static List<String> mustNotBeCurves = Arrays.asList(new String[]{"NIST P-192", "1.2.840.10045.3.1.1"});

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws InstantiationException, IllegalAccessException {
        TestResult r = new TestServices().doTest();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    public TestResult doTest() throws InstantiationException, IllegalAccessException {
        int seenCurves = 0;
        Set<String> types = new HashSet<>();
        //for "storing" of passes
        List<String> removeableMustBeCurves = new ArrayList<>(mustBeCurves.length);
        removeableMustBeCurves.addAll(Arrays.asList(mustBeCurves));
        //for storing of failures
        List<String> foundBadCurves = new ArrayList<>(0);
        System.out.println("running: " + this.getClass().getName());
        System.out.println("provider curves aliases");
        System.out.println("--------------------------------------------");
        for (Provider provider : Security.getProviders()) {
            System.out.println(provider.getName());
            Set<Provider.Service> services = provider.getServices();
            System.out.println("\t**************curves**************");
            for (Provider.Service service : services) {
                seenCurves++;
                types.add(service.getType());
                System.out.println("\t" + seenCurves + ") " + service.getAlgorithm() + " (" + service.getType() + ")");
                if (removeableMustBeCurves.remove(service.getAlgorithm())) {
                    System.out.println("test hit: this curve was requested");
                }
                if (mustNotBeCurves.contains(service.getAlgorithm())) {
                    System.out.println("test hit: this curve was supposed to be missing");
                    foundBadCurves.add(service.getAlgorithm());
                }
                if (Settings.testAliases) {
                    List<String> aliases = Misc.getAliases(service);
                    for (String alias : aliases) {
                        seenCurves++;
                        if (Settings.VerbositySettings.printAliases) {
                            System.out.println("\t\t" + seenCurves + ") " + alias + " (" + service.getType() + ")");
                        }
                        if (removeableMustBeCurves.remove(alias)) {
                            System.out.println("\t\ttest hit: this curve was requested");
                        }
                        if (mustNotBeCurves.contains(alias)) {
                            System.out.println("test hit: this curve was supposed to be missing");
                            foundBadCurves.add(service.getAlgorithm());
                        }
                    }
                }

            }
        }
        System.out.println("Known types size: " + types.size());
        List<Class<? extends AlgorithmTest>> alltests = ClassFinder.findAllAlgorithmTest();
        for (Class<? extends AlgorithmTest> testClass : alltests) {
            AlgorithmTest test = testClass.newInstance();
            types.remove(test.getTestedPart());
        }
        System.out.println("Missing to test types: " + types);
        System.out.println("Missing to test types: " + types.size() + "; see list above");
        String result = "Checked " + seenCurves + " services\n";
        int apearingBadCurves = foundBadCurves.size();
        if (apearingBadCurves == 0) {
            result += "no bad curve appeared (from total of " + mustNotBeCurves.size() + ": " + Arrays.toString(mustNotBeCurves.toArray()) + ")\n";
        } else {
            result += foundBadCurves.size() + " bad curves (namely: " + Arrays.toString(foundBadCurves.toArray()) + ") appeared (from total of " + mustNotBeCurves.size() + ": " + Arrays.toString(mustNotBeCurves.toArray()) + ")\n";
        }
        int missingExpectedCurves = removeableMustBeCurves.size();
        if (missingExpectedCurves == 0) {
            result += "all expected curves appeared (from total of " + mustBeCurves.length + ": " + Arrays.toString(mustBeCurves) + ")\n";
        } else {
            result += removeableMustBeCurves.size() + " expected curves (namely: " + Arrays.toString(removeableMustBeCurves.toArray()) + ") did not appeared (from total of " + mustBeCurves.length + ": " + Arrays.toString(mustBeCurves) + ")\n";
        }
        int failures = apearingBadCurves + missingExpectedCurves;
        result += "failed: " + failures + " services";
        if (failures == 0) {
            return TestResult.pass(result, this.getClass(), seenCurves);
        } else {
            return TestResult.fail(result, this.getClass(), seenCurves, failures);
        }

    }

}
