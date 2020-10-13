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
import static cryptotest.utils.KeysNaiveGenerator.getDsaPrivateKey;
import static cryptotest.utils.KeysNaiveGenerator.getEcPrivateKey;
import static cryptotest.utils.KeysNaiveGenerator.getRsaPrivateKey;
import static cryptotest.utils.KeysNaiveGenerator.getDsaPrivateKey1024;
import cryptotest.utils.TestResult;
import cryptotest.utils.Misc;

import java.security.*;
import java.security.spec.PSSParameterSpec;

/*
 * IwishThisCouldBeAtTest
 */
public class SignatureTests extends AlgorithmTest {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        TestResult r = new SignatureTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws AlgorithmInstantiationException, AlgorithmRunException {
        try {
            Signature sig = Signature.getInstance(alias, service.getProvider());
            //most of them are happy with rsa...
            PrivateKey key = getRsaPrivateKey(service.getProvider());
            if (service.getAlgorithm().contains("EC")) {
                key = getEcPrivateKey(service.getProvider());
            } else if (service.getAlgorithm().contains("DSA")) {
                //if (service.getAlgorithm().contains("SHA1")) {
                    /* SHA1 is not sufficient for default DSA key size,
                       throwing:
                       java.security.InvalidKeyException: The security strength of SHA-1 digest algorithm is not sufficient for this key size

                       See:
                       https://bugs.java.com/view_bug.do?bug_id=8184341
                       http://hg.openjdk.java.net/jdk8u/jdk8u-dev/jdk/file/8a97a690a0b3/src/share/classes/sun/security/provider/DSA.java#l104

                       1024-bits is also needed for pkcs11 in fips mode, default size does not work there
                    */
                    key = getDsaPrivateKey1024(service.getProvider());
                    /*
                } else {
                    key = getDsaPrivateKey(service.getProvider());
                }
                */
            } else if (service.getAlgorithm().contains("RSASSA-PSS")){
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", service.getProvider());
                KeyPair kp = kpg.generateKeyPair();
                key = kp.getPrivate();
                sig.setParameter(new PSSParameterSpec(10));
            }
            sig.initSign(key);
            //NONEwithDSA needs 20bytes
            byte[] b = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
                15, 16, 17, 18, 19, 20};
            sig.update(b);
            byte[] res = sig.sign();
            AlgorithmTest.printResult(res);
        } catch (NoSuchAlgorithmException ex) {
            throw new AlgorithmInstantiationException(ex);
        } catch (InvalidKeyException | UnsupportedOperationException | InvalidParameterException | SignatureException |
                InvalidAlgorithmParameterException | ProviderException ex) {
            if (Misc.isPkcs11Fips(service.getProvider())
                && ex.getMessage().startsWith("Unknown mechanism:")
                && (service.getAlgorithm().equals("SHA512withDSA")
                    || service.getAlgorithm().equals("SHA384withDSA")
                    || service.getAlgorithm().equals("SHA256withDSA")
                    || service.getAlgorithm().equals("SHA224withDSA"))) {
                /* NOTABUG, see:
                   https://bugzilla.redhat.com/show_bug.cgi?id=1868744
                */
                return;
            }
            throw new AlgorithmRunException(ex);
        }

    }

    @Override
    public String getTestedPart() {
        return "Signature";
    }

}
