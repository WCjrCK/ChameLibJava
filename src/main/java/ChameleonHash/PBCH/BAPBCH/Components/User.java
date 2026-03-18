package ChameleonHash.PBCH.BAPBCH.Components;

import ChameleonHash.PBCH.Components.Attributes;
import ChameleonHash.PBCH.Components.SecretKey;
import utils.ElementCounter;

public abstract class User<A extends Attributes, SK extends SecretKey> {
    public A S;
    public SK sk;

    public abstract ElementCounter TheoSize();
}
