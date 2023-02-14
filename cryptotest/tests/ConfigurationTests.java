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

/*
 * @test
 * @modules java.base/java.security:open
 * @bug 1422738
 * @library /
 * @build cryptotest.tests.ConfigurationTests
 *        cryptotest.Settings
 *        cryptotest.utils.AlgorithmInstantiationException
 *        cryptotest.utils.AlgorithmRunException
 *        cryptotest.utils.AlgorithmTest
 *        cryptotest.utils.TestResult
 * @run main/othervm cryptotest.tests.ConfigurationTests
 */

package cryptotest.tests;

import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.TestResult;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.URIParameter;

public class ConfigurationTests extends AlgorithmTest {

    public static void main(String[] args) {
        TestResult r = new ConfigurationTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws AlgorithmInstantiationException,
            AlgorithmRunException {
        File configFile = null;
        try {
            configFile = createConfigFile("javax.security.auth.login.Configuration", ".conf");

            Configuration configuration = Configuration.getInstance(alias, new URIParameter(configFile.toURI()),
                    service.getProvider());

            configuration.refresh();
            AppConfigurationEntry[] entries = configuration.getAppConfigurationEntry("test");
            // check whether properties read from configuration file are ok
            if (!"cryptotest.tests.ConfigurationTests".equals(entries[0].getLoginModuleName()) ||
                    !AppConfigurationEntry.LoginModuleControlFlag.REQUIRED.equals(entries[0].getControlFlag())) {
                throw new UnsupportedOperationException("No Configuration info for " + service.getAlgorithm() + " in" +
                        service.getProvider().getName());
            }
        } catch (NoSuchAlgorithmException e) {
            throw new AlgorithmInstantiationException(e);
        } catch (Exception e) {
            throw new AlgorithmRunException(e);
        } finally {
            if (configFile != null) {
                configFile.delete();
            }
        }
    }

    private File createConfigFile(String prefix, String suffix) throws IOException {
        File configFile = File.createTempFile(prefix, suffix);
        FileWriter fileWriter = new FileWriter(configFile);
        fileWriter.append("test {\n");
        fileWriter.append("    cryptotest.tests.ConfigurationTests required;\n");
        fileWriter.append("};\n");
        fileWriter.close();
        return configFile;
    }
}
