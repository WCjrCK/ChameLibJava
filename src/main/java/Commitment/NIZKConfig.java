package Commitment;

import EllipticCurve.Curve.Curve;

import java.util.HashMap;
import java.util.Map;

public class NIZKConfig {
    public Curve curve;
    public Map<String, Object> params;

    public NIZKConfig(Curve curve, Map<String, Object> params) {
        this.curve = curve;
        this.params = params;
    }

    public NIZKConfig(Curve curve) {
        this(curve, new HashMap<>());
    }

    public NIZKConfig() {
        this(null, new HashMap<>());
    }

}
