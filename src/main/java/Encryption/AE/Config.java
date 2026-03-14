package Encryption.AE;

import java.util.HashMap;
import java.util.Map;

public class Config {
    public AEName aeName;
    public Map<String, Object> params;

    public Config(AEName aeName, Map<String, Object> params) {
        this.aeName = aeName;
        this.params = params;
    }

    public Config(AEName aeName) {
        this(aeName, new HashMap<>());
    }
}
