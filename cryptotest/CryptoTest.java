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
package cryptotest;

import cryptotest.tests.TestProviders;
import cryptotest.tests.TestServices;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.ClassFinder;
import cryptotest.utils.TestResult;
import java.util.ArrayList;
import java.util.List;

/*
 * IwishThisCouldBeAtTest
 */
public class CryptoTest {

    /**
     * pseudo testclass for test checking that numebr of services was always
     * same
     */
    private static class ConstantServices {

    }

    /**
     * pseudo testclass for check that all services were tested
     */
    private static class NoAlgorithmMissed {

    }

    /**
     * @param args the command line arguments
     * @throws java.lang.InstantiationException
     * @throws java.lang.IllegalAccessException
     */
    public static void main(String[] args) throws InstantiationException, IllegalAccessException {

        List<Class<? extends AlgorithmTest>> alltests = ClassFinder.findAllAlgorithmTest();
        System.out.println("Loaded test files: " + alltests.size());
        List<TestResult> results = new ArrayList<>(alltests.size());
        for (Class<? extends AlgorithmTest> testClass : alltests) {
            AlgorithmTest test = testClass.newInstance();
            results.add(test.doTest());
        }

        results.add(new TestProviders().doTest());
        results.add(new TestServices().doTest());
        System.out.println("----------------------------------");
        int maxSeen = Integer.MIN_VALUE;
        int minSeen = Integer.MAX_VALUE;
        int totalAlghoritmsChecked = 0;
        for (TestResult r : results) {
            System.out.println(r.getExplanation());
            System.out.println(r.toString());
            if (r instanceof TestResult.AlgorithmTestResult) {
                maxSeen = Math.max(maxSeen, ((TestResult.AlgorithmTestResult) r).getSeen());
                minSeen = Math.min(minSeen, ((TestResult.AlgorithmTestResult) r).getSeen());
                totalAlghoritmsChecked += r.getSubtests();
            }
        }
        if (maxSeen != minSeen) {
            results.add(new TestResult("Number of checked services changed during test run", TestResult.State.FAILED, ConstantServices.class, 1, 1));
        } else {
            results.add(new TestResult("Number of checked services changed during test run", TestResult.State.PASSED, ConstantServices.class, 1, 0));
        }
        System.out.println(results.get(results.size() - 1).getExplanation());
        System.out.println(results.get(results.size() - 1).toString());
        if (maxSeen != totalAlghoritmsChecked) {
            results.add(new TestResult("Some algorithms missed! Checked " + totalAlghoritmsChecked + " from " + maxSeen, TestResult.State.FAILED, NoAlgorithmMissed.class, 1, 1));
        } else {
            results.add(new TestResult("Tested all " + totalAlghoritmsChecked + " algorithms", TestResult.State.PASSED, NoAlgorithmMissed.class, 1, 0));
        }
        System.out.println(results.get(results.size() - 1).getExplanation());
        System.out.println(results.get(results.size() - 1).toString());
        System.out.println("----------------------------------");
        int failures = 0;
        for (TestResult r : results) {
            System.out.println(r.toString());
            if (r.getState() == TestResult.State.FAILED) {
                failures++;
            }
        }
        System.out.println("Test runs: " + results.size() + "; failed :" + failures);
        if (failures > 0) {
            throw new RuntimeException("Some tests failed: " + failures);
        }

    }

}
