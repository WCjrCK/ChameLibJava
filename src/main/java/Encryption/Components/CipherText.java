package Encryption.Components;

import utils.ElementCounter;

public abstract class CipherText {
    public abstract boolean isEqual(Encryption.Components.CipherText o);

    public abstract ElementCounter TheoSize();
}
