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
 * IwishThisCouldBeAtTest
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
