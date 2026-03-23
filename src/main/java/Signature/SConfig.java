package Signature;

import java.util.HashMap;
import java.util.Map;

public class SConfig {
    public SName sName;
    public EllipticCurve.Curve.Config curveConfig;
    public Map<String, Object> params;

    public SConfig(SName sName, EllipticCurve.Curve.Config curveConfig, Map<String, Object> params) {
        this.sName = sName;
        this.curveConfig = curveConfig;
        this.params = params;
    }

    public SConfig(SName sName, EllipticCurve.Curve.Config curveConfig) {
        this(sName, curveConfig, new HashMap<>());
    }
}
