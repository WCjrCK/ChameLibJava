package Encryption.PKE;

import java.util.HashMap;
import java.util.Map;

public class Config {
    public PKEName PKEName;
    public Map<String, Object> params;

    public Config(PKEName PKEName, Map<String, Object> params) {
        this.PKEName = PKEName;
        this.params = params;
    }

    public Config(PKEName PKEName) {
        this(PKEName, new HashMap<>());
    }
}
