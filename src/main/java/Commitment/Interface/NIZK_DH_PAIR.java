package Commitment.Interface;

import Commitment.Components.Proof;
import Commitment.Components.Relation;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;

public interface NIZK_DH_PAIR<P extends Proof<P, R>, R extends Relation> {
    R createRelation(MultivePoint u, MultivePoint g, MultivePoint v, MultivePoint h);

    R createRelation(Scalar x, MultivePoint u, MultivePoint g, MultivePoint v, MultivePoint h);

    P Commitment(R data);
}