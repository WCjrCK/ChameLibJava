package ChameleonHash.PBCH.RevocablePBCH.Components;

import utils.ElementCounter;

public abstract class DecryptKey<I extends Info> {
    public I info;

    public abstract ElementCounter TheoSize();
}
