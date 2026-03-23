package Encryption.ABE.MAABE.RW_2015;

import utils.ElementCounter;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class PublicKeyGroup extends Encryption.ABE.MAABE.Components.PublicKeyGroup<PublicKey, Attribute> {
    List<PublicKey> PKS = new ArrayList<>();
    HashMap<Attribute, Integer> rho = new HashMap<>();

    @Override
    public void AddPK(PublicKey pk, Attribute attr) {
        rho.put(attr, PKS.size());
        PKS.add(pk);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
