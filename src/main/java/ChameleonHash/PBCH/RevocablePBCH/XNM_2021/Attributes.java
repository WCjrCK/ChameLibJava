package ChameleonHash.PBCH.RevocablePBCH.XNM_2021;

import utils.ElementCounter;

import java.util.HashSet;
import java.util.Set;

public class Attributes extends ChameleonHash.PBCH.RevocablePBCH.Components.Attributes {
    public Set<String> attrs = new HashSet<>();

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
