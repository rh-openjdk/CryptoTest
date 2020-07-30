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
import cryptotest.utils.KeysNaiveGenerator;
import cryptotest.utils.TestResult;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.PBEParameterSpec;

/*
 * IwishThisCouldBeAtTest
 */
public class MacTests extends AlgorithmTest {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        TestResult r = new MacTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws AlgorithmInstantiationException, AlgorithmRunException {
        try {
            Mac md = Mac.getInstance(alias, service.getProvider());
            byte[] b = new byte[]{1, 2, 3};

            if (service.getAlgorithm().contains("PBE")) {
                //cool, the pbe key is not ointerface pbekey, so salt do nto bubble formkey to algorithm:-/
                Key key = KeysNaiveGenerator.getPbeKeyWithSalt();
                //so we need to pass salt and ioterations by param
                PBEParameterSpec parmas = new PBEParameterSpec(new byte[]{1, 2, 3, 4, 5, 6, 7, 8}, 5);
                md.init(key, parmas);
            } else {
                KeyGenerator kg;
                try {
                    kg = KeysNaiveGenerator.getKeyGenerator(service.getAlgorithm(), service.getProvider());
                } catch (NoSuchAlgorithmException e) {
                    // No KeyGenerator, which could generate compatible keys found
                    // so just return here
                    return;
                }
                Key key = kg.generateKey();
                md.init(key);
            }

            md.update(b);
            printResult(md.doFinal());
        } catch (NoSuchAlgorithmException ex) {
            throw new AlgorithmInstantiationException(ex);
        } catch (InvalidKeyException | InvalidKeySpecException | InvalidAlgorithmParameterException ex) {
            throw new AlgorithmRunException(ex);
        }

    }

    @Override
    public String getTestedPart() {
        return "Mac";
    }

}
