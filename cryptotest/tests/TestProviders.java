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
import cryptotest.utils.TestResult;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

/*
 * IwishThisCouldBeAtTest
 */
public class TestProviders {

    private static String[] mustBeProviders;
    private static List<String> mustNotBeProviders;

    static {
        String v = System.getProperty("java.version");
        //currently we have it on on jdk7 on rhels only
        if (v.startsWith("1.7")) {
            mustBeProviders = new String[]{"SunPKCS11-NSS"};
            mustNotBeProviders = Arrays.asList(new String[]{});
        } else {
            mustBeProviders = new String[]{};
            mustNotBeProviders = Arrays.asList(new String[]{"SunPKCS11-NSS"});
        }
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        TestResult r = new TestProviders().doTest();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();

    }

    public TestResult doTest() {
        int seenProviders = 0;
        //for "storing" of passes
        List<String> removeableMustBeProviders = new ArrayList<>(mustBeProviders.length);
        removeableMustBeProviders.addAll(Arrays.asList(mustBeProviders));
        //for storing of failures
        List<String> foundBadProviders = new ArrayList<>(0);
        System.out.println("running: " + this.getClass().getName());
        System.out.println("provider\tatts");
        System.out.println("--------------------------------------------");
        for (Provider provider : Security.getProviders()) {
            seenProviders++;
            System.out.println(seenProviders + ") " + provider.getName());
            if (removeableMustBeProviders.remove(provider.getName())) {
                System.out.println("test hit: this provider was requested");
            }
            if (mustNotBeProviders.contains(provider.getName())) {
                System.out.println("test hit: this provider was supposed to be missing");
                foundBadProviders.add(provider.getName());
            }
            if (Settings.VerbositySettings.printAtts) {
                System.out.println("\t**************atts**************");
                Set<Map.Entry<Object, Object>> s = provider.entrySet();
                for (Map.Entry<Object, Object> entry : s) {
                    System.out.println("\t" + entry.getKey() + "=" + entry.getValue());
                }
                for (String key : provider.stringPropertyNames()) {
                    System.out.println("\t" + key + "=" + provider.getProperty(key));
                }
            }

        }
        String result = "Checked " + seenProviders + " providers\n";
        int apearingbadProviders = foundBadProviders.size();
        if (apearingbadProviders == 0) {
            result += "no bad provider appeared (from total of " + mustNotBeProviders.size() + ": " + Arrays.toString(mustNotBeProviders.toArray()) + ")\n";
        } else {
            result += foundBadProviders.size() + " bad providers (namely: " + Arrays.toString(foundBadProviders.toArray()) + ") appeared (from total of " + mustNotBeProviders.size() + ": " + Arrays.toString(mustNotBeProviders.toArray()) + ")\n";
        }
        int missingExpectedProviders = removeableMustBeProviders.size();
        if (missingExpectedProviders == 0) {
            result += "all expected providers appeared (from total of " + mustBeProviders.length + ": " + Arrays.toString(mustBeProviders) + ")]n";
        } else {
            result += removeableMustBeProviders.size() + " expected providers (namely: " + Arrays.toString(removeableMustBeProviders.toArray()) + ") did not appeared (from total of " + mustBeProviders.length + ": " + Arrays.toString(mustBeProviders) + ")\n";
        }
        int failures = apearingbadProviders + missingExpectedProviders;
        result += "failed: " + failures + " providers";
        if (failures == 0) {
            return TestResult.pass(result, this.getClass(), seenProviders);
        } else {
            return TestResult.fail(result, this.getClass(), seenProviders, failures);
        }

    }

}
