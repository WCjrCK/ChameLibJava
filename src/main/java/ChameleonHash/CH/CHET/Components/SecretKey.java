package ChameleonHash.CH.CHET.Components;

import utils.ElementCounter;

public abstract class SecretKey<SK extends SecretKey<SK>> {
    public abstract void CopyFrom(SK o);

    public abstract ElementCounter TheoSize();
}
