package Encryption.ABE.RevocableABE.XNM_2021;

import utils.ElementCounter;

public class PlainText extends Encryption.ABE.Components.PlainText<PlainText> {
    protected Encryption.ABE.BaseABE.FAME.PlainText FAME_pt;

    public boolean isEqual(PlainText o) {
        return FAME_pt.isEqual(o.FAME_pt);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
