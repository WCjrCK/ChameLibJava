package Commitment;

import EllipticCurve.Curve.Curve;

import java.util.HashMap;
import java.util.Map;

public class NIZKConfig {
    public NIZKName scheme;
    public Curve curve;
    public Map<String, Object> params;

    public NIZKConfig(NIZKName scheme, Curve curve, Map<String, Object> params) {
        this.scheme = scheme;
        this.curve = curve;
        this.params = params;
    }

    public NIZKConfig(NIZKName scheme, Curve curve) {
        this(scheme, curve, new HashMap<>());
    }

    public NIZKConfig(NIZKName scheme) {
        this(scheme, null, new HashMap<>());
    }
}
