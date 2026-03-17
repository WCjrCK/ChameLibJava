package Encryption.ABE.RevocableABE.Components;

import Encryption.ABE.ABEConfig;
import Encryption.ABE.Components.*;
import utils.ElementCounter;

public abstract class PublicParam<
        MPK extends MasterPublicKey,
        MSK extends MasterSecretKey,
        SK extends SecretKey,
        PT extends PlainText<PT>,
        CT extends CipherText<CT>
        > extends Encryption.ABE.Components.PublicParam<MPK, MSK, SK, PT, CT> {
    protected PublicParam(ABEConfig abeConfig) {
        super(abeConfig);
    }

    public abstract Attributes createAttributes();

    public abstract MPK createMasterPublicKey();

    public abstract MSK createMasterSecretKey();

    public abstract SK createSecretKey();

    public abstract PT createPlainText(String msg);

    public abstract CT createCipherText();

    public abstract ElementCounter TheoSize();
}
