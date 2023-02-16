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
import java.security.Provider;
import java.security.Security;

public class Misc {

    /* checks if provider is pksc11 in FIPS mode */
    public static boolean isPkcs11Fips(Provider p) {
        if (p.getName().equals("SunPKCS11-NSS-FIPS")) {
            return true;
        }
        return false;
    }

    /* checks if there is pkcs11 FIPS provider in list of providers */
    public static boolean pkcs11FipsPresent() {
        for (Provider p : Security.getProviders()) {
            if (isPkcs11Fips(p)) {
                return true;
            }
        }
        return false;
    }

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
        return "agent.brq." + getAgentDomain();
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

    // Based on:
    // https://github.com/openjdk/jdk/blob/9b911b492f56fbf94682535a1d20dde07c62940f/test/jdk/sun/security/mscapi/AllTypes.java#L55
    public static boolean hasWindowsAdmin() {
        try {
            Process p = Runtime.getRuntime().exec("reg query \"HKU\\S-1-5-19\"");
            p.waitFor();
            return (p.exitValue() == 0);
        } catch (Exception ex) {}
        return false;
    }

}
