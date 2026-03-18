package ChameleonHash.PBCH.BasePBCH.Components;

import utils.ElementCounter;

public abstract class HashValue<H extends HashValue<H>> {
    public abstract boolean isEqual(H other);

    public abstract ElementCounter TheoSize();
}
