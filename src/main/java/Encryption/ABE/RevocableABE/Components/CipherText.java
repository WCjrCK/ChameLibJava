package Encryption.ABE.RevocableABE.Components;

import utils.ElementCounter;

public abstract class CipherText<CT extends CipherText<CT>> {
    public abstract boolean isEqual(CT o);

    public abstract ElementCounter TheoSize();
}
