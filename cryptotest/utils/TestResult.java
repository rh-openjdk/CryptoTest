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
package cryptotest.utils;

public class TestResult {

    public void assertItself() {
        if (state.equals(State.FAILED)){
            throw new RuntimeException(test.getName()+" failed with explanantion of "+explanation.length()+" chars long");
        }
    }

    public static enum State {

        PASSED, FAILED;
    }

    private final String explanation;
    private final State state;
    private final Class test;
    private final int subtests;
    private final int failures;

    public TestResult(String explanation, State state, Class c, int total, int failures) {
        this.explanation = explanation;
        this.state = state;
        test = c;
        subtests = total;
        this.failures = failures;
    }

    public int getSubtests() {
        return subtests;
    }

    public static TestResult pass(String expl, Class c, int total) {
        return new TestResult(expl, State.PASSED, c, total, 0);
    }

    public static TestResult fail(String expl, Class c, int total, int failures) {
        return new TestResult(expl, State.FAILED, c, total, failures);
    }

    public String getExplanation() {
        return "Total checks: " + subtests + ", failed: " + failures + "\n"
                + explanation;
    }

    public Class getTest() {
        return test;
    }

    public State getState() {
        return state;
    }

    @Override
    public String toString() {
        return state.name() + ": " + test.getName();
    }

    //to distuinguish from other test results
    public static class AlgorithmTestResult extends TestResult {

        private final int seen;

        public int getSeen() {
            return seen;
        }

        public AlgorithmTestResult(String explanation, State state, Class c, int total, int failures, int seen) {
            super(explanation, state, c, total, failures);
            this.seen = seen;
        }

        public static AlgorithmTestResult fail(String expl, Class c, int total, int failures, int seen) {
            return new AlgorithmTestResult(expl, State.FAILED, c, total, failures, seen);
        }

        public static AlgorithmTestResult pass(String expl, Class c, int total, int seen) {
            return new AlgorithmTestResult(expl, State.PASSED, c, total, 0, seen);
        }

    }
}
