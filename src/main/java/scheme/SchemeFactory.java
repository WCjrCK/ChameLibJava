package scheme;

import EllipticCurve.Curve.CurveName;
import scheme.Components.PublicParam;
import scheme.IBCH.IBCHFactory;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import static scheme.SchemeType.*;

public class SchemeFactory {
    private SchemeFactory() {}

    public static Scheme createScheme(SchemeName schemeName, CurveName curveName, Map<String, Object> params) {
        checkParams(schemeName, curveName, params);
        if (schemeName.checkType(IBCH)) return IBCHFactory.createScheme(schemeName, params);
        throw new IllegalArgumentException("尚未支持当前方案：" + schemeName.name());
    }

    public static PublicParam createPublicParam(SchemeName schemeName, CurveName curveName, Map<String, Object> params) {
        checkParams(schemeName, curveName, params);
        if (schemeName.checkType(IBCH)) return IBCHFactory.createPublicParam(schemeName, curveName, params);
        throw new IllegalArgumentException("尚未支持当前方案：" + schemeName.name());

    }

    private static void checkParams(SchemeName schemeName, CurveName curveName, Map<String, Object> params) {
        Objects.requireNonNull(schemeName, "方案名称不能为空");
        Objects.requireNonNull(curveName, "曲线名称不能为空");
        Collections.unmodifiableMap(new LinkedHashMap<>(
                Objects.requireNonNull(params, "方案参数不能为空")
        ));
        if(!params.containsKey("curve_param")) throw new IllegalArgumentException("必须包含曲线参数（curve_param）");
    }
}
