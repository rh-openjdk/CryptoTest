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
import cryptotest.utils.TestResult;
import java.security.*;
import java.security.cert.CertSelector;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.LDAPCertStoreParameters;
import java.util.Arrays;
import java.util.Collection;

/*
 * IwishThisCouldBeAtTest
 */
public class CertStoreTests extends AlgorithmTest {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        TestResult r = new CertStoreTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws AlgorithmInstantiationException, AlgorithmRunException {
        try {
            CertStoreParameters p = null;
            if (alias.equals("LDAP")) {
                p = new LDAPCertStoreParameters();
                //this needs ldap server to finish
                return;
            } else {
                p = new CollectionCertStoreParameters();
            }
            CertStore ks = CertStore.getInstance(alias, p, service.getProvider());
            printResult(ks.getType());
            Collection<? extends java.security.cert.Certificate> cl = ks.getCertificates(new CertSelector() {
                @Override
                public boolean match(java.security.cert.Certificate cert) {
                    return true;
                }

                @Override
                public Object clone() {
                    try {
                        return super.clone();
                    } catch (Exception ex) {;
                        ex.printStackTrace();
                        return null;
                    }
                }
            });
            if (cl == null) {
                throw new AlgorithmRunException(new RuntimeException("Was nto possible to iterate through certstore"));
            }
            printResult(Arrays.toString(cl.toArray()));
        } catch (NoSuchAlgorithmException ex) {
            throw new AlgorithmInstantiationException(ex);
        } catch (Exception ex) {
            throw new AlgorithmRunException(ex);
        }
    }

    @Override

    public String getTestedPart() {
        return "CertStore";
    }

}
