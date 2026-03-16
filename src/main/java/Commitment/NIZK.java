package Commitment;

import Commitment.Components.Proof;
import Commitment.Components.Relation;
import Commitment.Interface.NIZK_DL;
import EllipticCurve.Curve.Curve;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;

public abstract class NIZK<P extends Proof<P, R>, R extends Relation>
implements NIZK_DL<P, R> {
    protected Curve curve;

    public abstract R createRelation(MultivePoint g, MultivePoint y);

    public abstract R createRelation(Scalar x, MultivePoint g, MultivePoint y);

    public abstract P Commitment(R data);
}
