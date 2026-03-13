package scheme.CH.Components;

import utils.ElementCounter;

public interface PublicParam {
    Message createMessage(String msg);

    PublicKey createPublicKey();

    SecretKey createSecretKey();

    HashValue createHashValue();

    Randomness createRandomness();

    String toString();

    ElementCounter TheoSize();
}
