package Commitment;

import Commitment.DL.NIZK_DL.Scheme;

public enum NIZKName {
    DL(Scheme.class),
//    EQUAL_DL,
//    REPRESENT,
//    DH_PAIR,
    ;

    Class<?> schemeClass;


    NIZKName(Class<?> scheme) {
        this.schemeClass = scheme;
    }
}
