package Commitment.Interface;

import Commitment.Components.Proof;
import Commitment.Components.Witness;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;

public interface NIZK_DL<P extends Proof<P, R>, R extends Witness> {
    R createRelation(MultivePoint g, MultivePoint y);

    R createRelation(Scalar x, MultivePoint g, MultivePoint y);

    P Prove(R data);
}
