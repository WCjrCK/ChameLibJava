package Encryption.PKE.Components;

import utils.ElementCounter;

public abstract class PlainText<PT extends PlainText<PT>> {
    public abstract boolean isEqual(PT o);

    public abstract byte[] getBytes();

    public abstract String toString();

    public abstract ElementCounter TheoSize();
}
