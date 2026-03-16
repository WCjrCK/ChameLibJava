package Encryption.ABE;

import java.util.HashMap;
import java.util.Map;

public class ABEConfig {
    public ABEName abeName;
    public EllipticCurve.Curve.Config curveConfig;
    public Map<String, Object> params;

    public ABEConfig(ABEName abeName, EllipticCurve.Curve.Config curveConfig, Map<String, Object> params) {
        this.abeName = abeName;
        this.curveConfig = curveConfig;
        this.params = params;
    }

    public ABEConfig(ABEName abeName, EllipticCurve.Curve.Config curveConfig) {
        this(abeName, curveConfig, new HashMap<>());
    }
}
