package Encryption.ABE.RevocableABE.TMM_2022;

import utils.ElementCounter;

import java.util.HashMap;

public class Revocated extends Encryption.ABE.RevocableABE.Components.Revocated {
    public HashMap<User, Integer> revocated = new HashMap<>();

    public void Add(User user, Info info) {
        revocated.put(user, info.timestamp);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
