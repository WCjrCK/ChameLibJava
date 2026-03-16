package Encryption.SE;

import java.util.HashMap;
import java.util.Map;

public class SEConfig {
    public SEName seName;
    public Map<String, Object> params;

    public SEConfig(SEName seName, Map<String, Object> params) {
        this.seName = seName;
        this.params = params;
    }

    public SEConfig(SEName seName) {
        this(seName, new HashMap<>());
    }
}
