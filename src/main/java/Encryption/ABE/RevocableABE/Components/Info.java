package Encryption.ABE.RevocableABE.Components;

import utils.ElementCounter;

import java.util.HashMap;

public abstract class Info {
    public abstract void setValue(HashMap<String, Object> map);

    public abstract ElementCounter TheoSize();
}
