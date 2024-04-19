import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.Callable;

public class PropDeps implements Callable<Map<String, String>> {

    boolean checkProp(String var) {
        String varval = System.getProperty(var);
        if (varval == null) { return true; }
        return ! varval.equalsIgnoreCase("1");
    }

    @Override
    public Map<String, String> call() {
        Map<String, String> map = new HashMap<String, String>();
        map.put("cryptotests.krb.kdc.enabled", checkProp("cryptotests.skipAgentTests") ? "true": "false");
        return map;
    }

    public static void main(String[] args) {
        for (Map.Entry<String,String> entry: new PropDeps().call().entrySet()) {
            System.out.println(entry.getKey() + ": " + entry.getValue());
        }
    }
}
