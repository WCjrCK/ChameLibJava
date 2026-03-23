package Encryption.ABE;

import ChameleonHash.SchemeCurveRequire;
import Encryption.ABE.BaseABE.FAME.Scheme;

public enum ABEName {
    ABE_FAME(SchemeCurveRequire.ALL, Scheme.class, false, false),
    RABE_XNM_2021(SchemeCurveRequire.ALL, Encryption.ABE.RevocableABE.XNM_2021.Scheme.class, true, false),
    RABE_TMM_2022(SchemeCurveRequire.ALL, Encryption.ABE.RevocableABE.TMM_2022.Scheme.class, true, false),
    MAABE_RW_2015(SchemeCurveRequire.ALL, Encryption.ABE.MAABE.RW_2015.Scheme.class, false, true),
    ;

    public final SchemeCurveRequire schemeCurveRequire;
    public final Class<?> schemeClass;
    public final boolean revokable;
    public final boolean multi_auth;

    ABEName(SchemeCurveRequire scr, Class<?> schemeClass, boolean revokable, boolean multi_auth) {
        this.schemeCurveRequire = scr;
        this.schemeClass = schemeClass;
        this.revokable = revokable;
        this.multi_auth = multi_auth;
    }
}
