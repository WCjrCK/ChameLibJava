package ChameleonHash.IBCH;

import ChameleonHash.IBCH.BaseIBCH.ZSS_2003.S1;
import ChameleonHash.IBCH.BaseIBCH.ZSS_2003.S2;
import ChameleonHash.IBCH.LabelIBCH.LJF_2025.Scheme;
import ChameleonHash.SchemeCurveRequire;
import EllipticCurve.Curve.CurveName;

import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static ChameleonHash.SchemeCurveRequire.ALL;
import static ChameleonHash.SchemeCurveRequire.SYMMETRIC;

public enum IBCHName {
    ZSS_2003_S1(ALL, S1.class, false),
    ZSS_2003_S2(SYMMETRIC, S2.class, false),
    CZS_2014(ALL, ChameleonHash.IBCH.BaseIBCH.CZS_2014.Scheme.class, false),
    XSL_2021(ALL, ChameleonHash.IBCH.BaseIBCH.XSL_2021.Scheme.class, false),
    LSX_2022(SYMMETRIC, ChameleonHash.IBCH.BaseIBCH.LSX_2022.Scheme.class, false),
    LJF_2025(SYMMETRIC, Scheme.class, true),
    ;

    public final SchemeCurveRequire schemeCurveRequire;
    public final Class<?> schemeClass;
    public final boolean has_label;

    private static final Map<String, IBCHName> LOOKUP = new ConcurrentHashMap<>();

    IBCHName(SchemeCurveRequire scr, Class<?> schemeClass, boolean has_label) {
        schemeCurveRequire = scr;
        this.schemeClass = schemeClass;
        this.has_label = has_label;
    }

    static {
        for (IBCHName value : values()) registerAlias(value.name(), value);
    }

    public static void registerAlias(String alias, IBCHName curve) {
        if (alias == null || alias.trim().isEmpty()) throw new IllegalArgumentException("方案别名不能为空");
        if (curve == null) throw new IllegalArgumentException("方案不能为空");
        LOOKUP.put(normalize(alias), curve);
    }

    public static IBCHName from(String name) {
        if (name == null) throw new IllegalArgumentException("方案名称不能为空");
        String key = normalize(name);
        IBCHName curve = LOOKUP.get(key);
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
