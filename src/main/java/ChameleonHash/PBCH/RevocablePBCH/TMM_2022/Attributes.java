package ChameleonHash.PBCH.RevocablePBCH.TMM_2022;

import utils.ElementCounter;

import java.util.HashSet;
import java.util.Set;

public class Attributes extends ChameleonHash.PBCH.RevocablePBCH.Components.Attributes {
    public Set<String> attrs = new HashSet<>();

    public Encryption.ABE.RevocableABE.Components.Attributes toRABEAttr() {
        Encryption.ABE.RevocableABE.Components.Attributes res = new Encryption.ABE.RevocableABE.Components.Attributes();
        res.attrs = new HashSet<>(attrs);
        return res;
    }

    public void addAttr(String attr) {
        attrs.add(attr);
    }

    public void CopyFrom(Attributes o) {
        attrs = new HashSet<>(o.attrs);
    }

    public ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
