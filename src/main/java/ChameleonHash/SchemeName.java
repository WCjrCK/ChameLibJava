package ChameleonHash;

import EllipticCurve.Curve.CurveName;

import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static ChameleonHash.SchemeCurveRequire.*;
import static ChameleonHash.SchemeType.CH;
import static ChameleonHash.SchemeType.IBCH;

public enum SchemeName {
    CH_LLA_2012(CH, SINGLEGROUP, ChameleonHash.CH.LLA_2012.Scheme.class),
    IBCH_ZSS_2003_S1(IBCH, ALL, ChameleonHash.IBCH.ZSS_2003.S1.class),
    IBCH_ZSS_2003_S2(IBCH, SYMMETRIC, ChameleonHash.IBCH.ZSS_2003.S2.class),
    IBCH_CZS_2014(IBCH, ALL, ChameleonHash.IBCH.CZS_2014.Scheme.class),
    IBCH_LSX_2022(IBCH, SYMMETRIC, ChameleonHash.IBCH.LSX_2022.Scheme.class),
    IBCH_XSL_2021(IBCH, ALL, ChameleonHash.IBCH.XSL_2021.Scheme.class),
    IBCH_LJF_2025(IBCH, SYMMETRIC, ChameleonHash.IBCH.LJF_2025.Scheme.class),
    ;

    public final SchemeType schemeType;
    public final SchemeCurveRequire schemeCurveRequire;
    public final Class<?> schemeClass;

    private static final Map<String, SchemeName> LOOKUP = new ConcurrentHashMap<>();

    SchemeName(SchemeType st, SchemeCurveRequire scr, Class<?> schemeClass) {
        schemeType = st;
        schemeCurveRequire = scr;
        this.schemeClass = schemeClass;
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

    public boolean checkCurve(CurveName curveName) {
        if (schemeCurveRequire == SYMMETRIC && !curveName.isSymmetic()) return false;
        return true;
    }

    private static String normalize(String value) {
        return value.trim().replace('-', '_').toUpperCase(Locale.ROOT);
    }
}
