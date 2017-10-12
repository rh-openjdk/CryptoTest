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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

/*
 * IwishThisCouldBeAtTest
 */
public class CertificateFactoryTests extends AlgorithmTest {

    /* 
    certificate used for testing, generated using:
    openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 9999
     */
    String certString
            = "-----BEGIN CERTIFICATE-----\n"
            + "MIIF0TCCA7mgAwIBAgIJANwEZ6nMcMK+MA0GCSqGSIb3DQEBCwUAMH8xCzAJBgNV\n"
            + "BAYTAkNaMRcwFQYDVQQIDA5DemVjaCBSZXB1YmxpYzENMAsGA1UEBwwEQnJubzEQ\n"
            + "MA4GA1UECgwHVGVzdGluZzEUMBIGA1UEAwwLZXhhbXBsZS5jb20xIDAeBgkqhkiG\n"
            + "9w0BCQEWEWVtYWlsQGV4YW1wbGUuY29tMB4XDTE3MDYwNzE2MTk1NVoXDTQ0MTAy\n"
            + "MjE2MTk1NVowfzELMAkGA1UEBhMCQ1oxFzAVBgNVBAgMDkN6ZWNoIFJlcHVibGlj\n"
            + "MQ0wCwYDVQQHDARCcm5vMRAwDgYDVQQKDAdUZXN0aW5nMRQwEgYDVQQDDAtleGFt\n"
            + "cGxlLmNvbTEgMB4GCSqGSIb3DQEJARYRZW1haWxAZXhhbXBsZS5jb20wggIiMA0G\n"
            + "CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCn8oY5vhqFT4eyDNxgvM282P5LF5cb\n"
            + "GC4paJUj3YziEDWPTah5kYnCFIONJI74iTOt2/ftjfjIX1zeVeJmZVkF4N3fmxWr\n"
            + "1WG1WaHUxXhcVQopZy7WGRvpQVUDo/eSxt34tBSUpkE0Nzrtt4kcjpFSxoCVNeRI\n"
            + "oPUT/y2tSi33pH52RHkFyb37zjgAWLTtMGA5hNUdZ7hjyzzp7UeQbm0Wu+ndbAut\n"
            + "Ybc4EJXB9l1Ia879lcGH4+IpspDWP1T8P31N+qJykHQVkwOSlycbPrxDGA6DjACV\n"
            + "OV5v/kAidqHWHCQGHYsqWfRQWylT/g84NpakHy1ubVkZuzEydK4qGi4qQGWrxTkU\n"
            + "b3fUq2kWb6ILFSWLuLHe0Q9QLZkysK4M0eDXV6/qV1iYbYngsFPKZzH7EizL0DmY\n"
            + "aqnpF2ZZ1Nr57TXxLQAo6ckEfaZSctBrqYvgyhwN9iX2z2Xv5skOBeWqrTmVQeLo\n"
            + "lZkEeimgm8Gh/w5NHhaJ04OuuX5D0FAkLViLMXv62CnKnYejr+49VAhmOVkHFkLW\n"
            + "ok3Vumr7+PJbsiz4w8tfLRFllgG1P8Qqb2YfMiTKOxemLnw1yjfLaJHtuTF92rCc\n"
            + "QvMzAiDm4c56+tq+n2RMZ0WhzrvB1wKBLmv91ISEDhSDq0PBtMY/rkKJCmCY7n1S\n"
            + "EXNJ/9IpRx8LmwIDAQABo1AwTjAdBgNVHQ4EFgQU29O5KKvS2ZoFcZnANd9f72gc\n"
            + "93YwHwYDVR0jBBgwFoAU29O5KKvS2ZoFcZnANd9f72gc93YwDAYDVR0TBAUwAwEB\n"
            + "/zANBgkqhkiG9w0BAQsFAAOCAgEAbFLYEPK7HMKdfXVrXlyn2AdQJahWuEdplll7\n"
            + "71spW7TzdSXr8jh/MwKiHF+3TXVRhpoYBmjdWqLQsBweyfwQmLYXxi68ATD+Jsg7\n"
            + "vkTQ1Xe4gOeQhM57rKVY2xyS9bS6rucWLWvoBR75mlQWnEfIkIWyhAnfj8zuKSCA\n"
            + "yQTsJKMHQBrX+vALTBsm3MFiN41y8VtkORtCii3w4y6rEg/iEIJ0Eq3rzzNoDKIC\n"
            + "3tNk4UZ4Ye3+IeeJxT9NJvyASRMrSLOPfvSK69sbvXP5DuD5x6f5t29iDZJMs8cG\n"
            + "EQbUVTU13VSP/9FrCsjqS/uk2c9sNPPuGZGgMBUbITXiS1+7IgruL34e7VWA/p9c\n"
            + "k/hcWxGIvHd64mP4FISX0xWFUCDbBr7oVTFWtuBheJUT82KXgbqjrS6ssFRqzfj5\n"
            + "SOjbbdhAC6PuuNy3bT+pYJyz/NMfUkGbJVIIcDG/Dbn1pEWb/1Q/LmB415vdeU9+\n"
            + "5x7EMPl0cX1KkOv/hzYMMDNjXptm6rOzZZZJfkdPge/jhPOU82RJvNuFOELcJ17m\n"
            + "Lm1Wu9rAo6zAK/HzMlig4iWg48U316polHi6gnYOpO8ADXKeSdM/XUh06DCnguTv\n"
            + "0NqoU+HQzZKhkcJgyqf58UUWb4Ng6Jo3l2je3jgBqWC0p7vgSYV2/7wLekGmvD9g\n"
            + "ZdOpVzI=\n"
            + "-----END CERTIFICATE-----\n";

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        TestResult r = new CertificateFactoryTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws
            AlgorithmInstantiationException, AlgorithmRunException {
        CertificateFactory cf = null;
        try {
            cf = CertificateFactory.getInstance(alias, service.getProvider());
            //designed for(service.getAlgorithm().equals("X.509"))  but attmpting for all with hope to fail
            byte[] certBytes = certString.getBytes(Charset.forName("UTF-8"));
            InputStream is = new ByteArrayInputStream(certBytes);

            Certificate cert = cf.generateCertificate(is);
            if (cert == null) {
                throw new AlgorithmRunException(
                        new NullPointerException("generated certificate is null"));
            }
        } catch (CertificateException | IllegalArgumentException ex) {
            if (cf == null) {
                throw new AlgorithmInstantiationException(ex);
            } else {
                throw new AlgorithmRunException(ex);
            }
        }
    }

    @Override
    public String getTestedPart() {
        return "CertificateFactory";
    }

}
