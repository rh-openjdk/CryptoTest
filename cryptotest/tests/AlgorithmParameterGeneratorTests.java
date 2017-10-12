/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptotest.tests;

import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.TestResult;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAGenParameterSpec;
import javax.crypto.spec.DHGenParameterSpec;


public class AlgorithmParameterGeneratorTests extends AlgorithmTest {

    public static void main(String[] args) {
        TestResult r = new AlgorithmParameterGeneratorTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws AlgorithmInstantiationException, AlgorithmRunException {

        try {
            AlgorithmParameterGenerator ap = AlgorithmParameterGenerator.getInstance(alias, service.getProvider());
            ap.init(1024, new SecureRandom());
            AlgorithmParameters algparams = ap.generateParameters();
            AlgorithmParameterSpec specparam;
            AlgorithmParameterGenerator ap2 = AlgorithmParameterGenerator.getInstance(alias, service.getProvider());
            if ("DSA".equals(alias)) {
                specparam = new DSAGenParameterSpec(1024, 160);
            } else {
                specparam = new DHGenParameterSpec(512, 12);
            }
            ap.init(specparam);
            AlgorithmParameters algparams2 = ap2.generateParameters();

        } catch (NoSuchAlgorithmException ex) {
            throw new AlgorithmInstantiationException(ex);
        } catch (InvalidAlgorithmParameterException ex) {
            throw new AlgorithmRunException(ex);
        }

    }

    @Override
    public String getTestedPart() {
        return "AlgorithmParameterGenerator";
    }
}
