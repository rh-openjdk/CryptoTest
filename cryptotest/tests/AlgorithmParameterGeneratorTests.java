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
            // use service.getAlgorithm rather then alias, since for some DSA, there are more aliases e.g. 1.2.840.10040.4.1
            if ("DSA".equals(service.getAlgorithm())) {
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
