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
/*
 * @test
 * @modules java.base/java.security:open
 * @bug 1422738
 * @library /
 * @build cryptotest.tests.TransformServiceTests
 *        cryptotest.utils.AlgorithmInstantiationException
 *        cryptotest.utils.AlgorithmRunException
 *        cryptotest.utils.AlgorithmTest
 *        cryptotest.utils.TestResult
 * @run main/othervm cryptotest.tests.TransformServiceTests
 */
package cryptotest.tests;

import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.TestResult;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import java.security.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import javax.xml.crypto.Data;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.TransformException;
import javax.xml.crypto.dsig.TransformService;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.crypto.dsig.spec.XPathFilter2ParameterSpec;
import javax.xml.crypto.dsig.spec.XPathFilterParameterSpec;
import javax.xml.crypto.dsig.spec.XPathType;
import javax.xml.crypto.dsig.spec.XSLTTransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

/*
 * IwishThisCouldBeAtTest
 */
public class TransformServiceTests extends AlgorithmTest {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        TestResult r = new TransformServiceTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }
 
    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws
            AlgorithmInstantiationException, AlgorithmRunException {
        try {
            boolean shouldMarshal = true;
            // By default we consider all algorithms as not working. See methods isKindOfWorking ans isTroubleMaker, which find those algorithms that are working.
            boolean isTroublemaker = true;
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setNamespaceAware(true);
            DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();

            String xslt
                    = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    + "<xsl:stylesheet version=\"2.0\" type=\"text/xsl\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\">\n"
                    + "   <xsl:template match=\"/\">\n"
                    + "      <html>\n"
                    + "         <body>\n"
                    + "            <p><xsl:value-of select=\"root/child/name\"/></p>\n"
                    + "            <p><xsl:value-of select=\"root/child/age\"/></p>\n"
                    + "         </body>\n"
                    + "      </html>\n"
                    + "   </xsl:template>\n"
                    + "</xsl:stylesheet>\n";

            String xml
                    = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    + "<root>\n"
                    + "   <child>\n"
                    + "<!-- comment -->\n"
                    + "      <name>name1</name>\n"
                    + "      <age>23</age>\n"
                    + "   </child>\n"
                    + "\n"
                    + "   <child>\n"
                    + "      <name>name2</name>\n"
                    + "      <age>25</age>\n"
                    + "   </child>\n"
                    + "<!-- comment -->\n"
                    + "</root>\n";

            InputStream xmlStream = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8));
            Data data = new OctetStreamData(xmlStream);
            DOMStructure xmlStructure;

            InputStream xsltStream = new ByteArrayInputStream(xslt.getBytes(StandardCharsets.UTF_8));
            Document xsltDocument = documentBuilder.parse(xsltStream);
            DOMStructure stylesheet = new DOMStructure(xsltDocument.getDocumentElement());
            TransformService ts = TransformService.getInstance(alias, "DOM", service.getProvider());
            final TransformParameterSpec params;
            if (service.getAlgorithm().endsWith("/REC-xslt-19991116")) {
                XSLTTransformParameterSpec spec = new XSLTTransformParameterSpec(stylesheet);
                params = spec;
            } else if (service.getAlgorithm().endsWith("/xmldsig-filter2")) {
                List<XPathType> list = new ArrayList<>();
                list.add(new XPathType("/", XPathType.Filter.UNION));
                params = new XPathFilter2ParameterSpec(list);
            } else if (service.getAlgorithm().endsWith("/REC-xpath-19991116")) {
                params = new XPathFilterParameterSpec("/");
            } else if (isKindOfWorkingAlgorithm(service.getAlgorithm())) {
                params = null;
                shouldMarshal = false;
                isTroublemaker = isTroublemaker(alias);
            } else {
                params = null;
            }

            if (isTroublemaker) {
                printResult("Troublemaking Transform Service, skipping usage part.");
            } else {
                ts.init(params);
                if (shouldMarshal) {

                    Document xmlDocument = documentBuilder.parse(xmlStream);
                    xmlStructure = new DOMStructure(xmlDocument.getDocumentElement());
                    ts.marshalParams(xmlStructure, null);
                }

                OctetStreamData output = (OctetStreamData) ts.transform(data, null);
                Scanner scan = new Scanner(output.getOctetStream()).useDelimiter("\\A");
                String result = scan.hasNext() ? scan.next() : "";
                printResult("output: \n" + result);
            }

        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException ex) {
            throw new AlgorithmInstantiationException(ex);
        } catch (UnsupportedOperationException | InvalidParameterException | ProviderException | TransformException | ParserConfigurationException
                | SAXException | IOException | MarshalException ex) {
            throw new AlgorithmRunException(ex);
        }
    }
    
    /**
     * Prevents from using aliases that cause failures during transformation
     * 'cause TransformService is unable to find Canonicalizer for that
     * particular alias
     *
     * @param alias
     * @return whether the alias is a troublemaker
     */
    private static boolean isTroublemaker(String alias) {
        return alias.equals("EXCLUSIVE") || alias.equals("INCLUSIVE_WITH_COMMENTS") || alias.equals("INCLUSIVE") || alias.equals("EXCLUSIVE_WITH_COMMENTS");
    }
    
    /**
     * This method checks if the algorithm is known to be working. If it is
     * working, it doesn't mean it's working for all aliases. See
     * isTroublemaking method.
     *
     * @param algorithm
     * @return
     */
    private static boolean isKindOfWorkingAlgorithm(String algorithm) {
        return algorithm.endsWith("/xml-c14n11#WithComments") || algorithm.endsWith("/xml-exc-c14n#")
                || algorithm.endsWith("/REC-xml-c14n-20010315#WithComments") || algorithm.endsWith("/REC-xml-c14n-20010315")
                || algorithm.endsWith("/xml-exc-c14n#WithComments") || algorithm.endsWith("/xml-c14n11");
    }

    @Override
    public String getTestedPart() {
        return "TransformService";
    }

}
