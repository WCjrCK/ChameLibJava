package Signature;

import EllipticCurve.Curve.CurveName;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public class SFactory {
    private SFactory() {}

    public static S createS(SName sName, CurveName curveName, Map<String, Object> params) {
        checkParams(sName, curveName, params);
        switch (sName) {
//            case BLS: return new BLS.
            default: throw new IllegalArgumentException("尚未支持当前方案：" + sName.name());
        }
    }

    private static void checkParams(SName sName, CurveName curveName, Map<String, Object> params) {
        Objects.requireNonNull(sName, "方案名称不能为空");
        Objects.requireNonNull(curveName, "曲线名称不能为空");
        Collections.unmodifiableMap(new LinkedHashMap<>(
                Objects.requireNonNull(params, "方案参数不能为空")
        ));
        if(!params.containsKey("curve_param")) throw new IllegalArgumentException("必须包含曲线参数（curve_param）");
        if (!sName.checkCurve(curveName)) throw new IllegalArgumentException("方案 " + sName.name() + " 不支持非对称群 " + curveName.name());
    }
}
