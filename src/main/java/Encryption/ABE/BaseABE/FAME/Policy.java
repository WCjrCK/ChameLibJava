package Encryption.ABE.BaseABE.FAME;

import MathStructure.LSSS;
import utils.ElementCounter;

public class Policy extends Encryption.ABE.Components.Policy {
    public LSSS MSP = new LSSS();

    @Override
    public ElementCounter TheoSize() {
        return null;
    }
}
