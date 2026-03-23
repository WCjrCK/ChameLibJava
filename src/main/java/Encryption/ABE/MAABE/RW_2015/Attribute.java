package Encryption.ABE.MAABE.RW_2015;

import utils.ElementCounter;

public class Attribute extends Encryption.ABE.MAABE.Components.Attribute {
    String attr;

    public Attribute(String a) {
        attr = a;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        return attr.equals(((Attribute) o).attr);
    }

    @Override
    public int hashCode() {
        return attr.hashCode();
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
