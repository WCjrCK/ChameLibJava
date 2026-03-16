package Commitment;

import Commitment.DL.NIZK_DL;

public enum NIZKName {
    DL(NIZK_DL.class),
//    EQUAL_DL,
//    REPRESENT,
//    DH_PAIR,
    ;

    Class<?> schemeClass;


    NIZKName(Class<?> scheme) {
        this.schemeClass = scheme;
    }
}
