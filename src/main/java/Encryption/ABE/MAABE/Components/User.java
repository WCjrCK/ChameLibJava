package Encryption.ABE.MAABE.Components;

import utils.ElementCounter;

import java.util.HashSet;
import java.util.Set;

public abstract class User<
        PP extends PublicParam,
        AUTH extends Authority,
        PKG extends PublicKeyGroup,
        SKG extends SecretKeyGroup,
        ID extends Identity,
        P extends Policy,
        PT extends PlainText<PT>,
        CT extends CipherText<CT, P>,
        A extends Attribute
        > {
    public PKG pkg;
    public SKG skg;
    public Set<A> owned_attr = new HashSet<>();
    public final ID id;

    protected User(ID id) {
        this.id = id;
    }

    public abstract void AddAttr(A attr);

    public abstract void KeyGen(PP pp, AUTH auth);

    public abstract void Encrypt(CT ct, PP pp, P P, PT pt);

    public abstract void Decrypt(PT pt, PP pp, CT ct);

    public abstract ElementCounter TheoSize();
}
