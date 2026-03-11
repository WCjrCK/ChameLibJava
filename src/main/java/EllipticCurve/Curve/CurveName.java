package EllipticCurve.Curve;

import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import EllipticCurve.Curve.implement.CurveImplementLib;
import static EllipticCurve.Curve.implement.CurveImplementLib.*;

public enum CurveName {
    A(PBC, true),
    A1(PBC, true),
    E(PBC, true),

    D_159(PBC, false), D_201(PBC, false), D_224(PBC, false),
    D_105171_196_185(PBC, false), D_277699_175_167(PBC, false), D_278027_190_181(PBC, false),

    F(PBC, false), SM_9(PBC, false),
    G_149(PBC, false),
    PBC_CUSTOM(PBC, false),

    BN254(CurveImplementLib.MCL, false),
    BLS12_381(CurveImplementLib.MCL, false),
    SECP256K1(CurveImplementLib.MCL, false);

    private final CurveImplementLib implementLib;
    private final boolean symmetric;

    private static final Map<String, CurveName> LOOKUP = new ConcurrentHashMap<>();
    
    CurveName(CurveImplementLib implementLib, boolean symmetric) {
        this.implementLib = implementLib;
        this.symmetric = symmetric;
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

    public boolean isSymmetic() {
        return symmetric;
    }
}
