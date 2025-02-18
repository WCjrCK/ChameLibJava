package scheme.IBCH;

import java.util.Random;

import curve.Group;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import utils.Func;

@SuppressWarnings("rawtypes")
public class PbcScheme {
    public Random rand = new Random();
    public Field G1,G2,GT,Zn;
    public Pairing pairing;

    public Element tmp_G, tmp_G_2, tmp_G_3, tmp_G_4;
    public Element tmp_H, tmp_H_2, tmp_H_3, tmp_H_4;
    public Element tmp_GT, tmp_GT_2, tmp_GT_3, tmp_GT_4;
    public Element tmp_Zn, tmp_Zn_2, tmp_Zn_3, tmp_Zn_4;

    // scheme with pairing
    public PbcScheme(curve.PBC curve, Group group_G1, Group group_G2) {
        pairing = Func.PairingGen(curve);

        G1 = Func.GetPBCField(pairing, group_G1);
        G2 = Func.GetPBCField(pairing, group_G2);
        GT = Func.GetPBCField(pairing, Group.GT);
        Zn = pairing.getZr();

        tmp_G = G1.newElement();
        tmp_G_2 = G1.newElement();
        tmp_G_3 = G1.newElement();
        tmp_G_4 = G1.newElement();

        tmp_H = G2.newElement();
        tmp_H_2 = G2.newElement();
        tmp_H_3 = G2.newElement();
        tmp_H_4 = G2.newElement();

        tmp_GT = GT.newElement();
        tmp_GT_2 = GT.newElement();
        tmp_GT_3 = GT.newElement();
        tmp_GT_4 = GT.newElement();

        tmp_Zn = Zn.newElement();
        tmp_Zn_2 = Zn.newElement();
        tmp_Zn_3 = Zn.newElement();
        tmp_Zn_4 = Zn.newElement();
    }

    // scheme without pairing
    public PbcScheme(curve.PBC curve, Group group) {
        pairing = Func.PairingGen(curve);

        G1 = Func.GetPBCField(pairing, group);
        Zn = pairing.getZr();

        tmp_G = G1.newElement();
        tmp_G_2 = G1.newElement();
        tmp_G_3 = G1.newElement();
        tmp_G_4 = G1.newElement();

        tmp_Zn = Zn.newElement();
        tmp_Zn_2 = Zn.newElement();
        tmp_Zn_3 = Zn.newElement();
        tmp_Zn_4 = Zn.newElement();
    }

    public Element GetImmutableRandomZnElement() {
        return Zn.newRandomElement().getImmutable();
    }

    public Element GetImmutableRandomG1Element(){
        return G1.newRandomElement().getImmutable();
    }

    public Element GetImmutableRandomG2Element(){
        return G2.newRandomElement().getImmutable();
    }

    public Element GetImmutableRandomGTElement(){
        return GT.newRandomElement().getImmutable();
    }

    public Element GetRandomZnElement(){
        return Zn.newRandomElement();
    }

    public Element GetRandomG1Element(){
        return G1.newRandomElement();
    }

    public Element GetRandomG2Element(){
        return G2.newRandomElement();
    }

    public Element GetRandomGTElement(){
        return GT.newRandomElement();
    }

    public void element_random(Element e) {
        e.setToRandom();
    }

    public void element_pow_zn(Element res, Element e, Element z) {
        res.set(e.powZn(z));
    }

    public void element_pairing(Element res, Element e1, Element e2) {
        res.set(pairing.pairing(e1, e2));
    }

    public void element_add(Element res, Element e1, Element e2){
        res.set(e1.add(e2));
    }

    public void element_sub(Element res, Element e1, Element e2){
        res.set(e1.sub(e2));
    }

    public void element_div(Element res, Element e1, Element e2){
        res.set(e1.div(e2));
    }

    public void element_mul(Element res, Element e1, Element e2){
        res.set(e1.mul(e2));
    }

    public void element_mul_zn(Element res, Element e, Element z){
        res.set(e.mulZn(z));
    }

    public void element_set(Element res, Element e){
        res = e.duplicate();
    }

    public int element_cmp(Element e1, Element e2){
        if(e1.isEqual(e2)){
            return 0;
        }else{
            return 1;
        }
    }


}
