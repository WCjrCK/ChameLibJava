package Encryption.ABE.MAABE.Components;

import utils.ElementCounter;

public abstract class PublicKeyGroup<PK extends PublicKey, A extends Attribute> {
    public abstract void AddPK(PK pk, A attr);

    public abstract ElementCounter TheoSize();
}
