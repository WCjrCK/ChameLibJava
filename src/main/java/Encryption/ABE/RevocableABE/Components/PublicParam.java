package Encryption.ABE.RevocableABE.Components;

import Encryption.ABE.ABEConfig;
import Encryption.ABE.Components.*;

public abstract class PublicParam<
        MPK extends MasterPublicKey,
        MSK extends MasterSecretKey,
        S extends State,
        R extends Revocated,
        A extends Authority,
        U extends User,
        I extends Info,
        KU extends UpdateKey<I>,
        SK extends SecretKey,
        DK extends DecryptKey<I>,
        PT extends PlainText<PT>,
        CT extends CipherText<CT>
        > extends Encryption.ABE.Components.PublicParam<MPK, MSK, SK, PT, CT> {
    protected PublicParam(ABEConfig abeConfig) {
        super(abeConfig);
    }
    public abstract A createAuthority();

    public abstract S createState();

    public abstract R createRevocated();

    public abstract U createUser(String ID);

    public abstract I createInfo();

    public abstract KU createKeyUpdater();

    public abstract DK createDecryptKey();
}
