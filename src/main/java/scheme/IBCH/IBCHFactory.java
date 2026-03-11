package scheme.IBCH;

import EllipticCurve.Curve.CurveName;
import scheme.IBCH.implement.ZSS_2003.S1.Impl;
import scheme.IBCH.implement.ZSS_2003.S1.PublicParam;
import scheme.Scheme;
import scheme.SchemeName;

import java.util.Map;

public class IBCHFactory {
    private IBCHFactory() {}

    public static Scheme createScheme(SchemeName schemeName, Map<String, Object> params) {
        switch (schemeName) {
            case IBCH_ZSS_2003_S1: return new Impl();
        }
        throw new IllegalArgumentException("尚未支持当前方案：" + schemeName.name());
    }

    public static scheme.Components.PublicParam createPublicParam(SchemeName schemeName, CurveName curveName, Map<String, Object> params) {
        switch (schemeName) {
            case IBCH_ZSS_2003_S1: return new PublicParam(curveName, params);
        }
        throw new IllegalArgumentException("尚未支持当前方案：" + schemeName.name());
    }
}
