package scheme.IBCH.Components;

import utils.ElementCounter;

public interface PublicParam {
    Message createMessage(String msg);

    Identity createIdentity(String ID);

    MasterSecretKey createMasterSecretKey();

    SecretKey createSecretKey();

    HashValue createHashValue();

    Randomness createRandomness();

    String toString();

    ElementCounter TheoSize();
}
