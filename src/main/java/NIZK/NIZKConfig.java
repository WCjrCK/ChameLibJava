package NIZK;

import EllipticCurve.Curve.Curve;

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
}
