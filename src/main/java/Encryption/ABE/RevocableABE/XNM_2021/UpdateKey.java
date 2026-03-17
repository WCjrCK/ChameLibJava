package Encryption.ABE.RevocableABE.XNM_2021;

import EllipticCurve.Point.MultivePoint;
import it.unisa.dia.gas.jpbc.Element;
import utils.ElementCounter;

import java.util.HashMap;

public class UpdateKey extends Encryption.ABE.RevocableABE.Components.UpdateKey<Info> {
    protected HashMap<Integer, MultivePoint> ku_theta_G1 = new HashMap<>(), ku_theta_G2 = new HashMap<>();

    public void AddKey(int theta, MultivePoint k_u_theta_0, MultivePoint k_u_theta_1) {
        ku_theta_G1.put(theta, k_u_theta_0);
        ku_theta_G2.put(theta, k_u_theta_1);
        Element[] res = new Element[2];
    }
    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
