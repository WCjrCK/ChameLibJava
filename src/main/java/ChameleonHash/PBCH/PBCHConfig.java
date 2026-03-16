package ChameleonHash.PBCH;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class PBCHConfig {
    public PBCHName schemeName;
    public EllipticCurve.Curve.Config curveConfig;
    public Map<String, Object> params;

    public PBCHConfig(PBCHName schemeName, EllipticCurve.Curve.Config curveConfig, Map<String, Object> params) {
        this.schemeName = Objects.requireNonNull(schemeName, "方案名称不能为空");
        this.curveConfig = Objects.requireNonNull(curveConfig, "曲线参数不能为空");
        if (!schemeName.checkCurve(curveConfig.curveName)) throw new IllegalArgumentException("方案 " + schemeName.name() + " 不支持非对称群 " + curveConfig.curveName.name());
        this.params = params;
    }

    public PBCHConfig(PBCHName schemeName, EllipticCurve.Curve.Config curveConfig) {
        this(schemeName, curveConfig, new HashMap<>());
    }
}
