package Encryption.ABE;

import java.util.HashMap;
import java.util.Map;

public class Config {
    public ABEName abeName;
    public EllipticCurve.Curve.Config curveConfig;
    public Map<String, Object> params;

    public Config(ABEName abeName, EllipticCurve.Curve.Config curveConfig, Map<String, Object> params) {
        this.abeName = abeName;
        this.curveConfig = curveConfig;
        this.params = params;
    }

    Config(ABEName abeName, EllipticCurve.Curve.Config curveConfig) {
        this(abeName, curveConfig, new HashMap<>());
    }
}
