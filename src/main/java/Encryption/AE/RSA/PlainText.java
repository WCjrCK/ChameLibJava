package Encryption.AE.RSA;

import utils.ElementCounter;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public class PlainText extends Encryption.Components.PlainText<PlainText> {
    public BigInteger pt;

    PlainText(String m) {
        pt = new BigInteger(1, m.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public final boolean isEqual(PlainText o) {
        return pt.equals(o.pt);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }

    @Override
    public final String toString() {
        return "pt = " + new String(pt.toByteArray());
    }
}
