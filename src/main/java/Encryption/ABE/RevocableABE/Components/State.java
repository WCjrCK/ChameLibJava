package Encryption.ABE.RevocableABE.Components;

import utils.ElementCounter;

public abstract class State<R extends Revocated, UK extends UpdateKey> {
    public R rl;
    public UK uk;

    public abstract ElementCounter TheoSize();
}
