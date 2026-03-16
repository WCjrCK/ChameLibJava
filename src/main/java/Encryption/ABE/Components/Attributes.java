package Encryption.ABE.Components;

import utils.ElementCounter;

import java.util.HashSet;
import java.util.Set;

public class Attributes {
    public Set<String> attrs = new HashSet<>();

    public void addAttr(String attr) {
        attrs.add(attr);
    }

    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
