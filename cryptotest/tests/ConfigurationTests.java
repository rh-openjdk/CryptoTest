package cryptotest.tests;

import cryptotest.utils.AlgorithmInstantiationException;
import cryptotest.utils.AlgorithmRunException;
import cryptotest.utils.AlgorithmTest;
import cryptotest.utils.TestResult;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.URIParameter;

public class ConfigurationTests extends AlgorithmTest {

    public static void main(String[] args) {
        TestResult r = new ConfigurationTests().mainLoop();
        System.out.println(r.getExplanation());
        System.out.println(r.toString());
        r.assertItself();
    }

    @Override
    protected void checkAlgorithm(Provider.Service service, String alias) throws AlgorithmInstantiationException,
            AlgorithmRunException {
        File configFile = null;
        try {
            final String configFileAbsPath = "/tmp/javax.security.auth.login.Configuration.conf";
            configFile = createConfigFile(configFileAbsPath);

            Configuration configuration = Configuration.getInstance(alias, new URIParameter(configFile.toURI()),
                    service.getProvider());

            configuration.refresh();
            AppConfigurationEntry[] entries = configuration.getAppConfigurationEntry("test");
            // check whether properties read from configuration file are ok
            if (!"cryptotest.tests.ConfigurationTests".equals(entries[0].getLoginModuleName()) ||
                    !AppConfigurationEntry.LoginModuleControlFlag.REQUIRED.equals(entries[0].getControlFlag())) {
                throw new UnsupportedOperationException("No Configuration info for " + service.getAlgorithm() + " in" +
                        service.getProvider().getName());
            }
        } catch (NoSuchAlgorithmException e) {
            throw new AlgorithmInstantiationException(e);
        } catch (Exception e) {
            throw new AlgorithmRunException(e);
        } finally {
            if (configFile != null) {
                configFile.delete();
            }
        }
    }

    private File createConfigFile(String path) throws IOException {
        File configFile = new File(path);
        if (configFile.exists()) {
            configFile.delete();
        }

        configFile.createNewFile();
        FileWriter fileWriter = new FileWriter(configFile);
        fileWriter.append("test {\n");
        fileWriter.append("    cryptotest.tests.ConfigurationTests required;\n");
        fileWriter.append("};\n");
        fileWriter.close();
        return configFile;
    }
}
