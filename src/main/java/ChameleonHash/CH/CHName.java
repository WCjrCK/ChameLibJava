package ChameleonHash.CH;

import ChameleonHash.SchemeCurveRequire;
import EllipticCurve.Curve.CurveName;

import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static ChameleonHash.SchemeCurveRequire.SINGLEGROUP;
import static ChameleonHash.SchemeCurveRequire.SYMMETRIC;

public enum CHName {
    CH_LLA_2012(SINGLEGROUP, ChameleonHash.CH.LabelCH.LLA_2012.Scheme.class, true, false),
    CH_CZT_2011(SINGLEGROUP, ChameleonHash.CH.LabelCH.CZT_2011.Scheme.class, true, false),
    CH_CZK_2004(SINGLEGROUP, ChameleonHash.CH.LabelCH.CZK_2004.Scheme.class, true, false),
    CH_CCT_2024(SINGLEGROUP, ChameleonHash.CH.BaseCH.CCT_2024.Scheme.class, false, false),
    ;

    public final SchemeCurveRequire schemeCurveRequire;
    public final Class<?> schemeClass;
    public final boolean has_label;
    public final boolean has_ET;

    private static final Map<String, CHName> LOOKUP = new ConcurrentHashMap<>();

    CHName(SchemeCurveRequire scr, Class<?> schemeClass, boolean has_label, boolean has_ET) {
        schemeCurveRequire = scr;
        this.schemeClass = schemeClass;
        this.has_label = has_label;
        this.has_ET = has_ET;
    }

    static {
        for (CHName value : values()) registerAlias(value.name(), value);
    }

    public static void registerAlias(String alias, CHName curve) {
        if (alias == null || alias.trim().isEmpty()) throw new IllegalArgumentException("方案别名不能为空");
        if (curve == null) throw new IllegalArgumentException("方案不能为空");
        LOOKUP.put(normalize(alias), curve);
    }

    public static CHName from(String name) {
        if (name == null) throw new IllegalArgumentException("方案名称不能为空");
        String key = normalize(name);
        CHName curve = LOOKUP.get(key);
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
