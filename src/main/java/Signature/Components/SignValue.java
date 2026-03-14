package Signature.Components;

import utils.ElementCounter;

public abstract class SignValue<S extends SignValue<S>> {
    public abstract boolean isEqual(S other);

    public abstract ElementCounter TheoSize();
}
