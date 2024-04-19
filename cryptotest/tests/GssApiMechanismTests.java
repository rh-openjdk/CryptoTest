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
 *          java.security.jgss/sun.security.jgss
 *          java.security.jgss/sun.security.jgss.krb5
 *          java.security.jgss/sun.security.krb5
 * @bug 1022017 1066099
 * @library /
 * @build cryptotest.tests.GssApiMechanismTests
 *        cryptotest.Settings
 *        cryptotest.utils.AlgorithmIgnoredException
 *        cryptotest.utils.AlgorithmInstantiationException
 *        cryptotest.utils.AlgorithmRunException
 *        cryptotest.utils.AlgorithmTest
 *        cryptotest.utils.Misc
 *        cryptotest.utils.TestResult
 * @requires cryptotests.krb.kdc.enabled == "true"
 * @run main/othervm cryptotest.tests.GssApiMechanismTests
 */

package cryptotest.tests;

import cryptotest.Settings;
import cryptotest.utils.AlgorithmIgnoredException;
import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.Misc;
import cryptotest.utils.TestResult;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import sun.security.jgss.GSSNameImpl;
import sun.security.jgss.krb5.Krb5NameElement;
import sun.security.krb5.PrincipalName;
import sun.security.krb5.Realm;
import sun.security.krb5.RealmException;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.util.ArrayList;
import java.util.Arrays;

public class GssApiMechanismTests extends AlgorithmTest {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        TestResult r = new GssApiMechanismTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }
    private final boolean debug = false;

    @Override
    protected void checkAlgorithm(final Provider.Service service, final String alias) throws AlgorithmInstantiationException, AlgorithmRunException {
        Misc.checkAgentConfig();
        try {
            if (debug) {
                System.setProperty("sun.security.jgss.debug", "true");
                System.setProperty("sun.security.krb5.debug", "true");
                System.setProperty("java.security.debug", "logincontext,policy,scl,gssloginconfig");
            }

            //first get TCK tgt
            ///see  http://icedtea.classpath.org/wiki/JCKDistilled#kerberos_prep for agent's setup
            // in adition to user 1+2, service principal is needed:
            //  admin.local:  addprinc -randkey http/service.redhat.com
            //    WARNING: no policy specified for http/service.redhat.com@JCKTEST; defaulting to no policy
            //    Principal "http/service.redhat.com@JCKTEST" created.
            //System.setProperty("java.security.krb5.realm", "JCKTEST");
            //System.setProperty("java.security.krb5.kdc", Misc.getAgentHostName());
            //setting the proeprties diable cross-realm authentication.
            //we must set krb5.cfg file
            File f = Misc.createTmpKrb5File();
            System.setProperty("java.security.krb5.conf", f.getAbsolutePath());
            final LoginContext lc = new LoginContext("user1", new Subject(), new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    for (Callback callback : callbacks) {
                        if (callback instanceof NameCallback) {
                            ((NameCallback) callback).setName("user1");;
                        }
                        if (callback instanceof PasswordCallback) {
                            ((PasswordCallback) callback).setPassword("user1".toCharArray());;
                        }
                    }
                }
            }, Misc.getKrb5Configuration());
            lc.login();
            final Subject subject = lc.getSubject();
            final Principal p = new ArrayList<>(subject.getPrincipals()).get(0);
            final KerberosTicket t = (KerberosTicket) new ArrayList<>(subject.getPrivateCredentials()).get(0);
            //this one is currently empty
            subject.getPublicCredentials();

            final GSSManager instance = GSSManager.getInstance();
            //surprisingly getMechsbyName did nto found a thing....
            //see names formechs in bellow
            final Oid[] b = instance.getMechs();
            Oid ffound = null;
            for (Oid oid : b) {
                if (oid.toString().equals(alias)) {
                    ffound = oid;
                }
            }
            if (ffound == null) {
                throw new RuntimeException("Manual search for " + alias + " in " + Arrays.toString(b) + " failed");
            }
            final Oid found = ffound;
            //thisis bad attempt to enforce provider as given by general contract of this testsute, as it will fallback to default if necessary
            instance.addProviderAtFront(service.getProvider(), found);
            Subject.doAs(subject, new PrivilegedAction<Object>() {
                @Override
                public Object run() {
                    try {
                        Oid[] names = instance.getNamesForMech(found);
                        for (Oid q : names) {
                            printResult(q.toString());
                            Oid[] a = instance.getMechsForName(q);
                            if (a.length == 0) {
                                throw new RuntimeException("more then 0 was expected for " + alias + " in " + service.getProvider() + " was " + a.length);
                            }
                            GSSName clientName = instance.createName("user1@JCKTEST", GSSName.NT_USER_NAME);
                            GSSCredential clientCred = instance.createCredential(clientName,
                                    8 * 3600,
                                    found,
                                    GSSCredential.INITIATE_ONLY);

                            GSSName serverName = instance.createName("http@service."+Misc.getAgentDomain(), GSSName.NT_HOSTBASED_SERVICE);

                            //finish(serverName); no longer needed, configfile do it for us
                            GSSContext context = instance.createContext(serverName,
                                    found,
                                    clientCred,
                                    //GSSContext.DEFAULT_LIFETIME);
                                    60);

                            context.requestMutualAuth(true);
                            context.requestConf(false);
                            context.requestInteg(true);

                            final byte[] outToken = context.initSecContext(new byte[0], 0, 0);
                            printResult(outToken);
                            final GSSCredential creds = instance.createCredential(clientName, 10, found, GSSCredential.INITIATE_AND_ACCEPT);
                            context.dispose();
                        }
                    } catch (GSSException ex) {
                        throw new RuntimeException(ex);
                    }
                    return null;
                }

                private void finish(GSSName serverName) {
                    try {
                        finishImpl(serverName);
                    } catch (Exception ex) {
                        ex.printStackTrace();
                    }
                }

                private void finishImpl(GSSName serverName) throws NoSuchFieldException, IllegalArgumentException, IllegalAccessException, RealmException {
                    Field f = GSSNameImpl.class.getDeclaredField("mechElement");
                    f.setAccessible(true);
                    Krb5NameElement o = (Krb5NameElement) f.get(serverName);
                    Field ff = Krb5NameElement.class.getDeclaredField("krb5PrincipalName");
                    ff.setAccessible(true);
                    PrincipalName oo = (PrincipalName) ff.get(o);
                    Field realmField = PrincipalName.class.getDeclaredField("nameRealm");
                    Field deductedField = PrincipalName.class.getDeclaredField("realmDeduced");
                    realmField.setAccessible(true);
                    deductedField.setAccessible(true);
                    deductedField.set(oo, false);
                    realmField.set(oo, new Realm("JCKTEST"));
                }

            });
        } catch (LoginException | RuntimeException ex) {
            throw new AlgorithmInstantiationException(ex);
        } catch (GSSException ex) {
            throw new AlgorithmRunException(ex);
        }

    }

    @Override
    public String getTestedPart() {
        return "GssApiMechanism";
    }


}
