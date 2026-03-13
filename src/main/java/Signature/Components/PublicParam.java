package Signature.Components;

import utils.ElementCounter;

public abstract class PublicParam {

    public abstract Message createMessage(String msg);

    public abstract SecretKey createSecretKey();

    public abstract PublicKey createPublicKey();

    public abstract SignValue createSignValue();

    public abstract ElementCounter TheoSize();
}
