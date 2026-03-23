package ChameleonHash.PBCH.MAPBCH.MXN_2022;

import utils.ElementCounter;

public class Identity extends ChameleonHash.PBCH.MAPBCH.Components.Identity {
    protected final Encryption.ABE.MAABE.Components.Identity MAABE_id;

    protected Identity(Encryption.ABE.MAABE.Components.Identity id) {
        this.MAABE_id = id;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Identity)) return false;
        return MAABE_id.equals(((Identity) o).MAABE_id);
    }

    @Override
    public int hashCode() {
        return MAABE_id.hashCode();
    }

    @Override
    public ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
