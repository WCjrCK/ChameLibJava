package ChameleonHash.PBCH.RevocablePBCH.Components;

import utils.ElementCounter;

public abstract class UpdateKey<I extends Info> {
    public I info;

    public abstract ElementCounter TheoSize();
}
