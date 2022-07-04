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

import java.net.MalformedURLException;
import java.net.URL;
import java.security.CodeSigner;
import java.security.CodeSource;
import java.security.NoSuchAlgorithmException;
import java.security.PermissionCollection;
import java.security.Policy;
import java.security.ProtectionDomain;
import java.security.Provider;
import java.util.PropertyPermission;

public class PolicyTests extends AlgorithmTest {

    public static void main(String[] args) {
        TestResult r = new PolicyTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws AlgorithmInstantiationException,
            AlgorithmRunException {
        try {
            final CodeSource codeSource = new CodeSource(new URL("http://localhost"), (CodeSigner[]) null);
            Policy policy = Policy.getInstance(alias, null, service.getProvider());

            policy.refresh();
            PermissionCollection permissions = policy.getPermissions(codeSource);
            boolean versionPolicy = policy.implies(new ProtectionDomain(codeSource, null),
                    new PropertyPermission("java.version", "read"));
            if (permissions == null || !versionPolicy) {
                throw new UnsupportedOperationException("Permission cant be reached for " + service.getAlgorithm() +
                        " in" + service.getProvider().getName());
            }
        } catch (NoSuchAlgorithmException e) {
            throw new AlgorithmInstantiationException(e);
        } catch (UnsupportedOperationException | MalformedURLException e) {
            throw new AlgorithmRunException(e);
        }
    }
}
