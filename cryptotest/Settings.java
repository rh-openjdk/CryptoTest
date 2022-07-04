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


public class Settings {

    private static boolean getBooleanProperty(String name, boolean defaultValue) {
        String val = System.getProperty(name);
        if (val != null) {
            String valLow = val.toLowerCase();
            if (valLow.equals("1") || valLow.equals("true")) {
                return true;
            } else if (valLow.equals("0") || valLow.equals("false")) {
                return false;
            }
        }
        return defaultValue;
    }

    public static boolean skipAgentTests = getBooleanProperty("cryptotests.skipAgentTests", false);
    //not only names of algorithms will be invoked, but also all aliases. Number of tests multiply by aprox 3, but right thing to do
    public static boolean testAliases = true;

    public static class VerbositySettings {

        public static boolean printAtts = true;
        public static boolean printAliases = true;
        //whether to stdout various byte[] crypto results
        public static boolean printResults = false;
        public static boolean printStacks = false;
    }

}
