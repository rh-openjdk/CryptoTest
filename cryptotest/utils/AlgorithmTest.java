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

import cryptotest.Settings;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


public abstract class AlgorithmTest {

    private List<Exception> failedInits = new ArrayList<>();
    private List<Exception> failedRuns = new ArrayList<>();
    private List<Exception> errorRuns = new ArrayList<>();
    private int algorithmsSeen = 0;
    private int testsCount = 0;
    private boolean run;

    public String getTestedPart() {
        return this.getClass().getSimpleName().substring(0, this.getClass().getSimpleName().indexOf("Tests"));
    }

    public String getAlgorithmExcludeList() {
      return null;
    }
    public String getAlgorithmAllowList() {
      return null;
    }

    protected abstract void checkAlgorithm(Provider.Service service, String alias) throws AlgorithmInstantiationException, AlgorithmRunException;

    private String generateTitle(Provider provider, Provider.Service service, String alias) {
        return Misc.generateTitle(testsCount, provider, service, alias);

    }

    public final TestResult doTest() {
        return mainLoop();
    }

    protected final TestResult mainLoop() {
        if (run) {
            throw new RuntimeException("This test already run. Make new instance");
        }
        System.out.println("running: " + this.getClass().getName());
        run = true;
        Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
            for (Provider.Service service : provider.getServices()) {
                //we can test each instance by its name or by its alias. Still setup is done only by name, as from
                // aliases it si very hard to be guessed
                for (String alias : Misc.createNames(service)) {
                    algorithmsSeen++;
                    String title = generateTitle(provider, service, alias);
                    try {
                        if (service.getType().equals(getTestedPart())) {
                            if (getAlgorithmExcludeList() != null) {
                                if (alias.matches(getAlgorithmExcludeList())) {
                                    continue;
                                }
                            }
                            if (getAlgorithmAllowList() != null) {
                                if (!alias.matches(getAlgorithmAllowList())) {
                                    continue;
                                }
                            }
                            System.out.println(title);
                            testsCount++;
                            checkAlgorithm(service, alias);
                            System.out.println("Passed");
                        }
                    } catch (AlgorithmIgnoredException ex) {
                        System.out.println("Ignored");
                    } catch (AlgorithmRunException ex) {
                        failedRuns.add(new Exception(title, ex));
                        System.out.println(ex);
                        System.out.println("failed to use: " + service.getAlgorithm() + " from " + provider);
                        System.out.println("Failed");
                        if (Settings.VerbositySettings.printStacks) {
                            System.err.println(title);
                            ex.printStackTrace();
                        }
                    } catch (AlgorithmInstantiationException ex) {
                        failedInits.add(new Exception(title, ex));
                        System.out.println(ex);
                        System.out.println("Failed to init: " + service.getAlgorithm() + " from " + provider);
                        System.out.println("Failed");
                        if (Settings.VerbositySettings.printStacks) {
                            System.err.println(title);
                            ex.printStackTrace();
                        }
                    } catch (Exception ex) {
                        errorRuns.add(new Exception(title, ex));
                        System.out.println(ex);
                        System.out.println("Error: " + service.getAlgorithm() + " from " + provider);
                        System.out.println("Error");
                        if (Settings.VerbositySettings.printStacks) {
                            System.err.println(title);
                            ex.printStackTrace();
                        }
                    }
                }

            }
        }
        int failed = (failedInits.size() + failedRuns.size() + errorRuns.size());
        TestResult.AlgorithmTestResult r;
        if (failed == 0) {
            r = TestResult.AlgorithmTestResult.pass("All " + getTestedPart() + " passed", this.getClass(), testsCount, algorithmsSeen);
        } else {

            String expl = failed + " " + getTestedPart() + " failed\n";
            expl = expl + "** failed runs: " + failedRuns.size() + " **\n";
            for (Exception ex : failedRuns) {
                StringWriter stack = new StringWriter();
                ex.printStackTrace(new PrintWriter(stack));
                expl += stack.toString();
            }
            expl = expl + "** failed inits: " + failedInits.size() + " **\n";
            for (Exception ex : failedInits) {
                StringWriter stack = new StringWriter();
                ex.printStackTrace(new PrintWriter(stack));
                expl += stack.toString();
            }
            expl = expl + "** error runs: " + errorRuns.size() + " **\n";
            for (Exception ex : errorRuns) {
                StringWriter stack = new StringWriter();
                ex.printStackTrace(new PrintWriter(stack));
                expl += stack.toString();
            }
            r = TestResult.AlgorithmTestResult.fail(expl, this.getClass(), testsCount, failed, algorithmsSeen);

        }
        return r;
    }

    protected static void printResult(String s) {
        if (Settings.VerbositySettings.printResults) {
            System.out.println(s);
        }
    }

    public static void printResult(int i) {
        printResult("[" + i + "]");
    }

    public static void printResult(byte[] res) {
        printResult(Arrays.toString(res));
    }
    
    public static void printResult(boolean res) {
        printResult(""+res);
    }

}
