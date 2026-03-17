package Encryption.ABE;

import Encryption.ABE.BaseABE.FAME.Scheme;

public enum ABEName {
    ABE_FAME(Scheme.class, false),
    RABE_XNM_2021(Encryption.ABE.RevocableABE.XNM_2021.Scheme.class, true),
    ;

    public Class<?> schemeClass;
    public boolean revokable;

    ABEName(Class<?> schemeClass, boolean revokable) {
        this.schemeClass = schemeClass;
        this.revokable = revokable;
    }
}
