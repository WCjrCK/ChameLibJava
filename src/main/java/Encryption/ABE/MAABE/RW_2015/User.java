package Encryption.ABE.MAABE.RW_2015;

import Encryption.ABE.MAABE.Components.Attribute;
import utils.ElementCounter;

public class User extends Encryption.ABE.MAABE.Components.User<
        PublicParam, Authority, PublicKeyGroup, SecretKeyGroup,
        Identity, Policy, PlainText, CipherText> {
    private final Core core = new Core();
    
    protected User(Identity id) {
        super(id);
    }

    @Override
    public void KeyGen(PublicParam pp, Authority auth) {
        for (Attribute attr : auth.controled_attr) {
            PublicKey pk = pp.createPublicKey();
            SecretKey sk = pp.createSecretKey();
            auth.KeyGen(pk, sk, pp, id, (Encryption.ABE.MAABE.RW_2015.Attribute) attr);
            pkg.AddPK(pk, (Encryption.ABE.MAABE.RW_2015.Attribute) attr);
            if (owned_attr.contains(attr)) skg.AddSK(sk, (Encryption.ABE.MAABE.RW_2015.Attribute) attr);
        }

    }

    @Override
    public void Encrypt(CipherText ct, PublicParam pp, Policy P, PlainText pt) {
        core.Encrypt(ct, pp, pkg, P, pt);
    }

    @Override
    public void Decrypt(PlainText pt, PublicParam pp, CipherText ct) {
        core.Decrypt(pt, pp, id, skg, ct);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
