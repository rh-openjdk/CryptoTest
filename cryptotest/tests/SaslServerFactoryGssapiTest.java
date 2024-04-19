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
 * @bug 1422738 1066099
 * @library /
 * @build cryptotest.tests.SaslServerFactoryTests
 *        cryptotest.Settings
 *        cryptotest.utils.AlgorithmIgnoredException
 *        cryptotest.utils.AlgorithmInstantiationException
 *        cryptotest.utils.AlgorithmRunException
 *        cryptotest.utils.AlgorithmTest
 *        cryptotest.utils.Misc
 *        cryptotest.utils.TestResult
 *        cryptotest.utils.SaslServerFactoryBase
 * @run main/othervm cryptotest.tests.SaslServerFactoryGssapiTest
 */

package cryptotest.tests;

import cryptotest.Settings;
import cryptotest.utils.AlgorithmIgnoredException;
import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.Misc;
import cryptotest.utils.TestResult;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.util.HashMap;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

public class SaslServerFactoryGssapiTest extends SaslServerFactoryBase {

    public static void main(String[] args) {
        TestResult r = new SaslServerFactoryGssapiTest().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    private final boolean debug = false;

    @Override
    protected void checkAlgorithm(Provider.Service service, final String alias)
            throws AlgorithmInstantiationException, AlgorithmRunException {
        try {
            setSaslProps();
            final Map<String, Object> props = new HashMap<>();
            if (alias.equals("GSSAPI")) {
                Misc.checkAgentConfig();
                if (debug) {
                    System.setProperty("sun.security.jgss.debug", "true");
                    System.setProperty("sun.security.krb5.debug", "true");
                    System.setProperty("java.security.debug", "logincontext,policy,scl,gssloginconfig");
                }
                final LoginContext lc = new LoginContext("user1", new Subject(), Misc.getNamePasswdRealmHandler(), Misc.getKrb5Configuration());
                lc.login();
                final Subject subject = lc.getSubject();
                Subject.doAs(subject, new PrivilegedSubjectAction(alias, props));
            } else {
              throw new AlgorithmIgnoredException();
            }
        } catch (LoginException ex) {
            throw new AlgorithmInstantiationException(ex);
        }
    }

    private class PrivilegedSubjectAction implements PrivilegedAction<Void> {

        private final String alias;
        private final Map<String, ?> props;

        public PrivilegedSubjectAction(String alias, Map<String, ?> props) {
            this.alias = alias;
            this.props = props;
        }

        @Override
        public Void run() {
            try {
                SaslServer server = Sasl.createSaslServer(alias,
                        "ldap", "JCKTEST", props, Misc.getNamePasswdRealmHandler());
                if (server == null) {
                    throw new RuntimeException("SaslServer is null");
                } else {
                    printResult("SaslServer has been successfully created.");
                }

            } catch (SaslException ex) {
                throw new RuntimeException(ex);
            }
            return null;
        }
    }
}
