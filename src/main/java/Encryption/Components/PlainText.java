package Encryption.Components;

import utils.ElementCounter;

public abstract class PlainText {
    public abstract boolean isEqual(Encryption.Components.PlainText o);

    public abstract String toString();

    public abstract ElementCounter TheoSize();
}
