package Encryption.ABE;

import Encryption.ABE.BaseABE.FAME.Scheme;

public enum ABEName {
    FAME(Scheme.class, false),
    ;

    public Class<?> schemeClass;
    public boolean revokable;

    ABEName(Class<?> schemeClass, boolean revokable) {
        this.schemeClass = schemeClass;
        this.revokable = revokable;
    }
}
