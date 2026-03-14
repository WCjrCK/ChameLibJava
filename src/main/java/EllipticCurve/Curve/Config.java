package EllipticCurve.Curve;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class Config {
    public CurveName curveName;
    public Map<String, Object> params;

    public Config(CurveName curveName, Map<String, Object> params) {
        this.curveName = Objects.requireNonNull(curveName, "曲线名称不能为空");
        this.params = params;
    }

    public Config(CurveName curveName) {
        this(curveName, new HashMap<>());
    }

}
