package ChameleonHash.CH.CHET.KOG_CDK_2017;

import Commitment.Components.Proof;
import EllipticCurve.Point.MultivePoint;
import Encryption.Components.CipherText;
import utils.ElementCounter;

public class Randomness extends ChameleonHash.CH.Components.Randomness {
    protected MultivePoint p;
    protected CipherText C;
    protected Proof pi_p;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}

