package Encryption.ABE.RevocableABE.Components;

import utils.ElementCounter;

public abstract class PlainText<PT extends PlainText<PT>> {
    public abstract boolean isEqual(PT o);

    public abstract ElementCounter TheoSize();
}
