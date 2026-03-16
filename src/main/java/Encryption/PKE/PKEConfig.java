package Encryption.PKE;

import java.util.HashMap;
import java.util.Map;

public class PKEConfig {
    public PKEName PKEName;
    public Map<String, Object> params;

    public PKEConfig(PKEName PKEName, Map<String, Object> params) {
        this.PKEName = PKEName;
        this.params = params;
    }

    public PKEConfig(PKEName PKEName) {
        this(PKEName, new HashMap<>());
    }
}
