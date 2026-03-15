package NIZK.Components;

import utils.ElementCounter;

public abstract class Proof<R extends Relation> {
    public abstract ElementCounter TheoSize();


    public abstract boolean Check(R data);
}
