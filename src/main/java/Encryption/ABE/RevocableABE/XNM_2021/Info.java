package Encryption.ABE.RevocableABE.XNM_2021;

import utils.ElementCounter;

import java.util.HashMap;

public class Info extends Encryption.ABE.RevocableABE.Components.Info {
    int timestamp;

    @Override
    public void setValue(HashMap<String, Object> map) {
        timestamp = (int) map.getOrDefault("timestamp", -1);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
