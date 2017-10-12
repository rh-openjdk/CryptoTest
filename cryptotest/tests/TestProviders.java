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
