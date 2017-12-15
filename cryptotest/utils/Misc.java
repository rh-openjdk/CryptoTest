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

import cryptotest.Settings;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.Provider;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.sasl.RealmCallback;

public class Misc {

    public static List<String> getAliases(Provider.Service service) {
        try {
            return getAliasesImpl(service);
        } catch (Exception ex) {
            ex.printStackTrace();
            System.out.println("Sry, reflection for aliases went mad");
            return new ArrayList<>(0);
        }
    }

    private static List<String> getAliasesImpl(Provider.Service service) throws
            InvocationTargetException, ClassNotFoundException, IllegalArgumentException, NoSuchMethodException,
            SecurityException, IllegalAccessException {
        Class cls = Class.forName("java.security.Provider$Service");
        Method m = cls.getDeclaredMethod("getAliases");
        m.setAccessible(true);
        return (List<String>) m.invoke(service);
    }

    /*
     this method creates list of all names algorithm is known by. NAme is first, aliases follows
     */
    static List<String> createNames(Provider.Service service) {
        List<String> r = new ArrayList<>(0);
        r.add(service.getAlgorithm());
        if (Settings.testAliases) {
            r.addAll(getAliases(service));
        }
        return r;
    }

    /*
    * geenrate name form counter, provider name, service name and service alias
     */
    static String generateTitle(int seen, Provider provider, Provider.Service service, String callName) {
        return seen + ")\t" + provider.getName() + ": \t" + service.getAlgorithm() + "~"
                + callName + "\t (" + service.getType() + ")";
    }

    public static String getAgentHostName() {
        return "agent." + getAgentDomain();
    }

    public static String getAgentDomain() {
        return "redhat.com";
    }

    public static File createTmpKrb5File() {
        File f = null;
        try {
            f = File.createTempFile("krb5", ".conf");
            f.deleteOnExit();
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
        try (FileWriter fw = new FileWriter(f)) {
            //the domain_realm record is serving instead of finish hacking method
            String s = "[libdefaults]\n"
                    + "default_realm = JCKTEST\n"
                    + "ticket_lifetime = 36000\n"
                    + "dns_lookup_realm = false\n"
                    + "dns_lookup_kdc = false\n"
                    + "ticket_lifetime = 24h\n"
                    + "renew_lifetime = 7d\n"
                    + "forwardable = true\n"
                    + "allow_weak_crypto = true"
                    + "\n"
                    + "[realms]\n"
                    + "JCKTEST = {\n"
                    + "kdc = " + getAgentHostName() + "\n"
                    + "admin_server = " + getAgentHostName() + "\n"
                    + "default_domain = JCKTEST\n"
                    + "}\n"
                    + "\n"
                    + "[domain_realm]\n"
                    + "." + getAgentDomain() + " = JCKTEST\n"
                    + "\n"
                    + "[appdefaults]\n"
                    + "autologin = true\n"
                    + "forward = true\n"
                    + "forwardable = true\n"
                    + "encrypt = true\n";
            fw.write(s);
            fw.flush();
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
        return f;
    }

    public static Configuration getKrb5Configuration() {
        return new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                return new AppConfigurationEntry[]{
                    new AppConfigurationEntry(
                    "com.sun.security.auth.module.Krb5LoginModule",
                    AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                    new HashMap()
                    )
                };
            }
        };
    }

    public static CallbackHandler getNamePasswdRealmHandler() {
        final String credentials = "user1";
        return new CallbackHandler() {
            @Override
            public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
                for (Callback callback : callbacks) {
                    if (callback instanceof NameCallback) {
                        ((NameCallback) callback).setName(credentials);
                    } else if (callback instanceof PasswordCallback) {
                        ((PasswordCallback) callback).setPassword(credentials.toCharArray());
                    } else if (callback instanceof RealmCallback) {
                        RealmCallback rc = (RealmCallback) callback;
                        rc.setText(rc.getDefaultText());
                    } else {
                        throw new UnsupportedCallbackException(callback, "Unrecognized SASL Callback");
                    }
                }
            }
        };
    }
}
