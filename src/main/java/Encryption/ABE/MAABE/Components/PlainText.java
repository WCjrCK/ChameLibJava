package Encryption.ABE.MAABE.Components;

import utils.ElementCounter;

public abstract class PlainText<PT extends PlainText<PT>> {
    public abstract boolean isEqual(PT o);

    public abstract byte[] toBytes();

    public abstract ElementCounter TheoSize();
}
