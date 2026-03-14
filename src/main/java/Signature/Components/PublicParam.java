package Signature.Components;

import utils.ElementCounter;

public abstract class PublicParam<
        PK extends PublicKey,
        SK extends SecretKey,
        M extends Message,
        S extends SignValue
        > {

    public abstract M createMessage(String msg);

    public abstract SK createSecretKey();

    public abstract PK createPublicKey();

    public abstract S createSignValue();

    public abstract ElementCounter TheoSize();
}
