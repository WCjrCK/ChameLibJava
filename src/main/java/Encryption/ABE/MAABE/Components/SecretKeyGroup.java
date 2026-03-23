package Encryption.ABE.MAABE.Components;

import utils.ElementCounter;

public abstract class SecretKeyGroup<SK extends SecretKey, A extends Attribute> {
    public abstract void AddSK(SK sk, A attr);

    public abstract ElementCounter TheoSize();
}
