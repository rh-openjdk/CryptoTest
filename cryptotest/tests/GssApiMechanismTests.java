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

import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.Misc;
import cryptotest.utils.TestResult;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Field;

import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
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

/*
 * IwishThisCouldBeAtTest
 */
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

                            GSSName serverName = instance.createName("http@service.redhat.com", GSSName.NT_HOSTBASED_SERVICE);

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
