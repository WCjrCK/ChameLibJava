package ChameleonHash.PBCH.BasePBCH.Components;

import utils.ElementCounter;

public abstract class HashValue<H extends HashValue<H, P>, P extends Policy> {
    public P P;

    public abstract boolean isEqual(H other);

    public abstract ElementCounter TheoSize();
}
