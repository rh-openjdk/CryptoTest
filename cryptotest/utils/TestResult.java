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
