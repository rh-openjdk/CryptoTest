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
