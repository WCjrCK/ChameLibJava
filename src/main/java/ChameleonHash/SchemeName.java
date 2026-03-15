package ChameleonHash;

import ChameleonHash.IBCH.LabelIBCH.LJF_2025.Scheme;
import EllipticCurve.Curve.CurveName;

import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static ChameleonHash.SchemeCurveRequire.*;
import static ChameleonHash.SchemeType.CH;
import static ChameleonHash.SchemeType.IBCH;

public enum SchemeName {
    CH_LLA_2012(CH, SINGLEGROUP, ChameleonHash.CH.LLA_2012.Scheme.class, true),
    CH_CZT_2011(CH, SINGLEGROUP, ChameleonHash.CH.CZT_2011.Scheme.class, true),
    CH_CZK_2004(CH, SINGLEGROUP, ChameleonHash.CH.CZK_2004.Scheme.class, true),
//    CH_KEF_MH_SDH_DL_AM_2004(CH, SINGLEGROUP, ChameleonHash.CH.KEF_MH_SDH_DL_AM_2004.Scheme.class),
//    CH_ET_KOG_CDK_2017(CH, SINGLEGROUP, ChameleonHash.CH.ET_KOG_CDK_2017.Scheme.class),
//    CH_FS_ECC_CCT_2024(CH, SINGLEGROUP, ChameleonHash.CH.FS_ECC_CCT_2024.Scheme.class),
//    CH_KEF_NoMH_AM_2004(CH, ALL, ChameleonHash.CH.KEF_NoMH_AM_2004.Scheme.class),
//    CH_KEF_MH_RSA_F_AM_2004(CH, ALL, ChameleonHash.CH.KEF_MH_RSA_F_AM_2004.Scheme.class),
//    CH_KEF_MH_RSANN_F_AM_2004(CH, ALL, ChameleonHash.CH.KEF_MH_RSANN_F_AM_2004.Scheme.class),
//    CH_CDK_2017(CH, ALL, ChameleonHash.CH.CDK_2017.Scheme.class),
//    CH_ET_BC_CDK_2017(CH, ALL, ChameleonHash.CH.ET_BC_CDK_2017.Scheme.class),
//    CHET_RSA_CDK_2017(CH, ALL, ChameleonHash.CH.RSA_CDK_2017.Scheme.class),

    IBCH_ZSS_2003_S1(IBCH, ALL, ChameleonHash.IBCH.ZSS_2003.S1.class, false),
    IBCH_ZSS_2003_S2(IBCH, SYMMETRIC, ChameleonHash.IBCH.ZSS_2003.S2.class, false),
    IBCH_CZS_2014(IBCH, ALL, ChameleonHash.IBCH.CZS_2014.Scheme.class, false),
    IBCH_LSX_2022(IBCH, SYMMETRIC, ChameleonHash.IBCH.LSX_2022.Scheme.class, false),
    IBCH_XSL_2021(IBCH, ALL, ChameleonHash.IBCH.XSL_2021.Scheme.class, false),
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
