package ChameleonHash.PBCH.MAPBCH.MXN_2022;

import utils.ElementCounter;

public class Attribute extends ChameleonHash.PBCH.MAPBCH.Components.Attribute {
    protected Encryption.ABE.MAABE.RW_2015.Attribute MAABE_attr;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Attribute)) return false;
        return MAABE_attr.equals(((Attribute) o).MAABE_attr);
    }

    @Override
    public int hashCode() {
        return MAABE_attr.hashCode();
    }

    @Override
    public ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
