package Encryption.ABE.MAABE.RW_2015;

import utils.ElementCounter;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class SecretKeyGroup extends Encryption.ABE.MAABE.Components.SecretKeyGroup<SecretKey, Attribute> {
    List<SecretKey> SKS = new ArrayList<>();
    HashMap<Attribute, Integer> rho = new HashMap<>();

    @Override
    public void AddSK(SecretKey sk, Attribute attr) {
        rho.put(attr, SKS.size());
        SKS.add(sk);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
