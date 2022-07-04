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
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Collections;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 *
 * @author oklinovs
 */
public class XMLSignatureFactoryTest extends AlgorithmTest {

    public static void main(String[] args) {
        TestResult r = new XMLSignatureFactoryTest().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws AlgorithmInstantiationException, AlgorithmRunException {
        try {       
            XMLSignatureFactory factory = XMLSignatureFactory.getInstance(alias, service.getProvider());
            
            Reference ref = factory.newReference("", factory.newDigestMethod(DigestMethod.SHA1, null),
                Collections.singletonList(factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec)null)), null, null);
            
            SignedInfo si = factory.newSignedInfo(factory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS, (XMLSignature)null), 
            factory.newSignatureMethod(SignatureMethod.DSA_SHA1, null), Collections.singletonList(ref));
            
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
            kpg.initialize(512);
            KeyPair kp = kpg.generateKeyPair();
            
            KeyInfoFactory kif = factory.getKeyInfoFactory();
            KeyValue kv = kif.newKeyValue(kp.getPublic());
        
            KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));
            
            XMLSignature xmlSignature = factory.newXMLSignature(si, ki);
            Document document = createXMLDocument();
            printResult(printDoc(document));
            DOMSignContext context = new DOMSignContext(kp.getPrivate(), document.getDocumentElement());
            xmlSignature.sign(context);
            printResult(printDoc(document));
                      
            
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | KeyException | ParserConfigurationException | MarshalException | XMLSignatureException e) {
            throw new AlgorithmInstantiationException(e);
        }
    }

    @Override
    public String getTestedPart() {
        return "XMLSignatureFactory";
    }
    
    private Document createXMLDocument() throws ParserConfigurationException
    {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().newDocument();
        Element root = doc.createElement("root");
        Element child = doc.createElement("child");
        Attr attr = doc.createAttribute("attribute");
        attr.setValue("value");
        child.setAttributeNode(attr);
        child.appendChild(doc.createTextNode("text"));
        doc.appendChild(root);
        root.appendChild(child);
        return doc;
    }
    
    private String printDoc(Document doc)
    {
        String output = "";
        try
        {
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(doc), new StreamResult(writer));
            output = writer.getBuffer().toString().replaceAll("\n|\r", "");
        }
        catch(TransformerConfigurationException e) {
            
        } catch (TransformerException ex) {
            
        }
        finally
        {
            return output;
        }
    }
}
