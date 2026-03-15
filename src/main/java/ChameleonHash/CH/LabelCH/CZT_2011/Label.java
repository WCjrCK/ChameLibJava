package ChameleonHash.CH.LabelCH.CZT_2011;

import utils.ElementCounter;

public class Label extends ChameleonHash.CH.LabelCH.Components.Label {
    protected String I;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
