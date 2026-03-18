package ChameleonHash.PBCH.RevocablePBCH.Components;

import utils.ElementCounter;

public abstract class User<A extends Attributes, SK extends SecretKey> {
    public A S;
    public SK sk;

    public abstract ElementCounter TheoSize();
}
