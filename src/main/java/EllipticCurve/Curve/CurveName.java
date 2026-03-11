package EllipticCurve.Curve;

import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import EllipticCurve.Curve.implement.CurveImplementLib;
public enum CurveName {
    A(CurveImplementLib.PBC),
    A1(CurveImplementLib.PBC),
    D_159(CurveImplementLib.PBC), D_201(CurveImplementLib.PBC), D_224(CurveImplementLib.PBC), D_105171_196_185(CurveImplementLib.PBC), D_277699_175_167(CurveImplementLib.PBC), D_278027_190_181(CurveImplementLib.PBC),
    E(CurveImplementLib.PBC),
    F(CurveImplementLib.PBC), SM_9(CurveImplementLib.PBC),
    G_149(CurveImplementLib.PBC),
    PBC_CUSTOM(CurveImplementLib.PBC),

    BN254(CurveImplementLib.MCL),
    BLS12_381(CurveImplementLib.MCL),
    SECP256K1(CurveImplementLib.MCL);

    private final CurveImplementLib implementLib;

    private static final Map<String, CurveName> LOOKUP = new ConcurrentHashMap<>();
    
    CurveName(CurveImplementLib implementLib) {
        this.implementLib = implementLib;
    }

    static {
        for (CurveName value : values()) registerAlias(value.name(), value);
        registerAlias("bls12381", BLS12_381);
        registerAlias("bls12-381", BLS12_381);
        registerAlias("secp-256k1", SECP256K1);
    }

    public static CurveName from(String name) {
        if (name == null) throw new IllegalArgumentException("曲线名称不能为空");
        String key = normalize(name);
        CurveName curve = LOOKUP.get(key);
        if (curve == null) throw new IllegalArgumentException("尚不支持当前曲线: " + name);
        return curve;
    }

    public static void registerAlias(String alias, CurveName curve) {
        if (alias == null || alias.trim().isEmpty()) throw new IllegalArgumentException("曲线别名不能为空");
        if (curve == null) throw new IllegalArgumentException("曲线不能为空");
        LOOKUP.put(normalize(alias), curve);
    }

    public boolean checkLib(CurveImplementLib lib) {
        return implementLib == lib;
    }

    private static String normalize(String value) {
        return value.trim().replace('-', '_').toUpperCase(Locale.ROOT);
    }
}
