package Encryption.SE;

import java.util.HashMap;
import java.util.Map;

public class Config {
    public SEName seName;
    public Map<String, Object> params;

    public Config(SEName seName, Map<String, Object> params) {
        this.seName = seName;
        this.params = params;
    }

    public Config(SEName seName) {
        this(seName, new HashMap<>());
    }
}
