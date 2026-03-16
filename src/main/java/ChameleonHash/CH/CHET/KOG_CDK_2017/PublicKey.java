package ChameleonHash.CH.CHET.KOG_CDK_2017;

import Commitment.Components.Proof;
import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class PublicKey extends ChameleonHash.CH.Components.PublicKey {
    protected MultivePoint h;
    protected Proof pi_pk;
    protected Encryption.PKE.Components.PublicKey pke_pk;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}

