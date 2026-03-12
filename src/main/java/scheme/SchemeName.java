package scheme;

import EllipticCurve.Curve.CurveName;

import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static scheme.SchemeType.*;
import static scheme.SchemeCurveRequire.*;

public enum SchemeName {
    IBCH_ZSS_2003_S1(IBCH, ALL),
    IBCH_ZSS_2003_S2(IBCH, SYMMETRIC),
    IBCH_CZS_2014(IBCH, ALL),
    IBCH_LSX_2022(IBCH, SYMMETRIC),
    IBCH_XSL_2021(IBCH, ALL),
    ;

    public final SchemeType schemeType;
    public final SchemeCurveRequire schemeCurveRequire;

    private static final Map<String, SchemeName> LOOKUP = new ConcurrentHashMap<>();

    SchemeName(SchemeType st, SchemeCurveRequire scr) {
        schemeType = st;
        schemeCurveRequire = scr;
    }

    static {
        for (SchemeName value : values()) registerAlias(value.name(), value);
    }

    public static void registerAlias(String alias, SchemeName curve) {
        if (alias == null || alias.trim().isEmpty()) throw new IllegalArgumentException("方案别名不能为空");
        if (curve == null) throw new IllegalArgumentException("方案不能为空");
        LOOKUP.put(normalize(alias), curve);
    }

    public static SchemeName from(String name) {
        if (name == null) throw new IllegalArgumentException("方案名称不能为空");
        String key = normalize(name);
        SchemeName curve = LOOKUP.get(key);
        if (curve == null) throw new IllegalArgumentException("尚不支持当前方案: " + name);
        return curve;
    }

    public boolean checkType(SchemeType type) {
        return schemeType == type;
    }

    public boolean checkCurve(CurveName curveName) {
        if (schemeCurveRequire == SYMMETRIC && !curveName.isSymmetic()) return false;
        return true;
    }

    private static String normalize(String value) {
        return value.trim().replace('-', '_').toUpperCase(Locale.ROOT);
    }
}
