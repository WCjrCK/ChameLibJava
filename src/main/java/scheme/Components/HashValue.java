package scheme.Components;

import utils.ElementCounter;

public abstract class HashValue implements scheme.CH.Components.HashValue, scheme.IBCH.Components.HashValue {
    public abstract boolean isEqual(HashValue other);

    public abstract ElementCounter TheoSize();
}
