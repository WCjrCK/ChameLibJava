package Encryption.ABE.RevocableABE.Components;

import utils.ElementCounter;

public abstract class SecretKey<DK extends DecryptKey, S extends Attributes> {
    public DK dk;
    public S S;

    public abstract ElementCounter TheoSize();
}
