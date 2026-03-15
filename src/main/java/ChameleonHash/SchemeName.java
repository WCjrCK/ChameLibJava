package ChameleonHash;

import ChameleonHash.IBCH.BaseIBCH.ZSS_2003.S1;
import ChameleonHash.IBCH.BaseIBCH.ZSS_2003.S2;
import ChameleonHash.IBCH.LabelIBCH.LJF_2025.Scheme;
import EllipticCurve.Curve.CurveName;

import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static ChameleonHash.SchemeCurveRequire.*;
import static ChameleonHash.SchemeType.CH;
import static ChameleonHash.SchemeType.IBCH;

public enum SchemeName {
    CH_LLA_2012(CH, SINGLEGROUP, ChameleonHash.CH.LabelCH.LLA_2012.Scheme.class, true),
    CH_CZT_2011(CH, SINGLEGROUP, ChameleonHash.CH.LabelCH.CZT_2011.Scheme.class, true),
    CH_CZK_2004(CH, SINGLEGROUP, ChameleonHash.CH.LabelCH.CZK_2004.Scheme.class, true),
    CH_CCT_2024(CH, SINGLEGROUP, ChameleonHash.CH.BaseCH.CCT_2024.Scheme.class, false),

    IBCH_ZSS_2003_S1(IBCH, ALL, S1.class, false),
    IBCH_ZSS_2003_S2(IBCH, SYMMETRIC, S2.class, false),
    IBCH_CZS_2014(IBCH, ALL, ChameleonHash.IBCH.BaseIBCH.CZS_2014.Scheme.class, false),
    IBCH_LSX_2022(IBCH, SYMMETRIC, ChameleonHash.IBCH.BaseIBCH.LSX_2022.Scheme.class, false),
    IBCH_XSL_2021(IBCH, ALL, ChameleonHash.IBCH.BaseIBCH.XSL_2021.Scheme.class, false),
    IBCH_LJF_2025(IBCH, SYMMETRIC, Scheme.class, true),
    ;

    public final SchemeType schemeType;
    public final SchemeCurveRequire schemeCurveRequire;
    public final Class<?> schemeClass;
    public final boolean has_label;

    private static final Map<String, SchemeName> LOOKUP = new ConcurrentHashMap<>();

    SchemeName(SchemeType st, SchemeCurveRequire scr, Class<?> schemeClass, boolean has_label) {
        schemeType = st;
        schemeCurveRequire = scr;
        this.schemeClass = schemeClass;
        this.has_label = has_label;
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
