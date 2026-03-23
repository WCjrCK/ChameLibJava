package ChameleonHash.PBCH.MAPBCH.MXN_2022;

import utils.ElementCounter;

import java.util.Objects;

public class Identity extends ChameleonHash.PBCH.MAPBCH.Components.Identity {
    protected final String id;
    protected final Encryption.ABE.MAABE.RW_2015.Identity MAABE_id;
    protected final Signature.Components.SignValue DS_sigma_gid;

    protected Identity(String id, Encryption.ABE.MAABE.RW_2015.Identity MAABE_id) {
        this(id, MAABE_id, null);
    }

    protected Identity(String id, Encryption.ABE.MAABE.RW_2015.Identity MAABE_id, Signature.Components.SignValue DS_sigma_gid) {
        this.id = Objects.requireNonNull(id, "身份不能为空");
        this.MAABE_id = Objects.requireNonNull(MAABE_id, "MA-ABE 身份不能为空");
        this.DS_sigma_gid = DS_sigma_gid;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Identity)) return false;
        Identity other = (Identity) o;
        return id.equals(other.id) && MAABE_id.equals(other.MAABE_id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, MAABE_id);
    }

    @Override
    public ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
