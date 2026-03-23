package ChameleonHash.PBCH;

import ChameleonHash.SchemeCurveRequire;
import EllipticCurve.Curve.CurveName;

import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static ChameleonHash.SchemeCurveRequire.ALL;
import static ChameleonHash.SchemeCurveRequire.SYMMETRIC;

public enum PBCHName {
    DSS_2019(ALL, ChameleonHash.PBCH.BasePBCH.DSS_2019.Scheme.class, false, false, false),
    TLL_2020(ALL, ChameleonHash.PBCH.BAPBCH.TLL_2020.Scheme.class, true, false, false),
    XNM_2021(ALL, ChameleonHash.PBCH.RevocablePBCH.XNM_2021.Scheme.class, false, true, false),
    TMM_2022(ALL, ChameleonHash.PBCH.RevocablePBCH.TMM_2022.Scheme.class, false, true, false),
    ZLW_2021(SYMMETRIC, ChameleonHash.PBCH.MAPBCH.ZLW_2021.Scheme.class, false, false, true),
    ;

    public final SchemeCurveRequire schemeCurveRequire;
    public final Class<?> schemeClass;
    public final boolean has_blackbox_accountability;
    public final boolean revocable;
    public final boolean multi_auth;

    private static final Map<String, PBCHName> LOOKUP = new ConcurrentHashMap<>();

    PBCHName(SchemeCurveRequire scr, Class<?> schemeClass, boolean hba, boolean revocable, boolean multi_auth) {
        schemeCurveRequire = scr;
        this.schemeClass = schemeClass;
        this.has_blackbox_accountability = hba;
        this.revocable = revocable;
        this.multi_auth = multi_auth;
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
