package Encryption.Components;

import utils.ElementCounter;

public abstract class PlainText<PT extends PlainText<PT>> {
    public abstract boolean isEqual(PT o);

    public abstract String toString();

    public abstract ElementCounter TheoSize();
}
