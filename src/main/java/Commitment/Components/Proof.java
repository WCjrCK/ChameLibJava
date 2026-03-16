package Commitment.Components;

import utils.ElementCounter;

public abstract class Proof<P extends Proof, R extends Relation> {
    public abstract ElementCounter TheoSize();

    public abstract void CopyFrom(P o);

    public abstract boolean Check(R data);
}
