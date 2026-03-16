package ChameleonHash.PBCH;

import ChameleonHash.SchemeCurveRequire;
import EllipticCurve.Curve.CurveName;

import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static ChameleonHash.SchemeCurveRequire.SINGLEGROUP;
import static ChameleonHash.SchemeCurveRequire.SYMMETRIC;

public enum PBCHName {
    CCT_2024(SINGLEGROUP, ChameleonHash.CH.BaseCH.CCT_2024.Scheme.class),
    DKS_2020(SINGLEGROUP, ChameleonHash.CH.BaseCH.DKS_2020.Scheme.class),
    DSS_2020(SINGLEGROUP, ChameleonHash.CH.BaseCH.DSS_2020.Scheme.class),

    LLA_2012(SINGLEGROUP, ChameleonHash.CH.LabelCH.LLA_2012.Scheme.class),
    CZT_2011(SINGLEGROUP, ChameleonHash.CH.LabelCH.CZT_2011.Scheme.class),
    CZK_2004(SINGLEGROUP, ChameleonHash.CH.LabelCH.CZK_2004.Scheme.class),
    AM_2004(SINGLEGROUP, ChameleonHash.CH.LabelCH.AM_2004.Scheme.class),

    KOG_CDK_2017(SINGLEGROUP, ChameleonHash.CH.CHET.KOG_CDK_2017.Scheme.class),
    BC_CDK_2017(SINGLEGROUP, ChameleonHash.CH.CHET.BC_CDK_2017.Scheme.class),
    ;

    public final SchemeCurveRequire schemeCurveRequire;
    public final Class<?> schemeClass;

    private static final Map<String, PBCHName> LOOKUP = new ConcurrentHashMap<>();

    PBCHName(SchemeCurveRequire scr, Class<?> schemeClass) {
        schemeCurveRequire = scr;
        this.schemeClass = schemeClass;
    }

    static {
        for (PBCHName value : values()) registerAlias(value.name(), value);
    }

    public static void registerAlias(String alias, PBCHName curve) {
        if (alias == null || alias.trim().isEmpty()) throw new IllegalArgumentException("方案别名不能为空");
        if (curve == null) throw new IllegalArgumentException("方案不能为空");
        LOOKUP.put(normalize(alias), curve);
    }

    public static PBCHName from(String name) {
        if (name == null) throw new IllegalArgumentException("方案名称不能为空");
        String key = normalize(name);
        PBCHName curve = LOOKUP.get(key);
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
