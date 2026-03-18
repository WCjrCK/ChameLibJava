package Encryption.ABE.RevocableABE.Components;

import utils.ElementCounter;

import java.util.HashSet;
import java.util.Set;

public class Attributes {
    public Set<String> attrs = new HashSet<>();

    public void addAttr(String attr) {
        attrs.add(attr);
    }

    public void CopyFrom(Attributes o) {
        attrs = new HashSet<>(o.attrs);
    }

    public Encryption.ABE.BaseABE.Components.Attributes toBaseABEAttr() {
        Encryption.ABE.BaseABE.Components.Attributes res = new Encryption.ABE.BaseABE.Components.Attributes();
        res.attrs = new HashSet<>(attrs);
        return res;
    }

    public ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
