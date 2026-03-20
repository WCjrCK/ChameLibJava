package ChameleonHash.CH.CHET.BC_CDK_2017;

import ChameleonHash.CH.CH;
import ChameleonHash.CH.CHConfig;
import ChameleonHash.Interface.CHET;

/*
 * Chameleon-Hashes with Ephemeral Trapdoors And Applications to Invisible Sanitizable Signatures
 * P11. Black-Box Construction: Bootstrapping
 */

public class Scheme extends CH
        implements CHET<PublicParam, PublicKey, SecretKey, Message, ETrapdoor, HashValue, Randomness> {
    @Override
    public final PublicParam createPublicParam(CHConfig config) {
        return new PublicParam(config);
    }

    @Override
    public final void Setup(PublicParam pp) {
        pp.CHScheme.Setup(pp.ch_pp);
    }

    @Override
    public final void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp) {
        pp.CHScheme.KeyGen(pk.ch_pk, sk.ch_sk, pp.ch_pp);
    }

    @Override
    public final void Hash(HashValue h, Randomness r, ETrapdoor etd, PublicParam pp, PublicKey pk, Message m) {
        pp.CHScheme.KeyGen(h.ch_pk, etd.ch_sk, pp.ch_pp);
        pp.CHScheme.Hash(h.h_1, r.r_1, pp.ch_pp, pk.ch_pk, m.m);
        pp.CHScheme.Hash(h.h_2, r.r_2, pp.ch_pp, h.ch_pk, m.m);
    }

    @Override
    public final boolean Verify(PublicParam pp, PublicKey pk, Message m, HashValue h, Randomness r) {
        return pp.CHScheme.Verify(pp.ch_pp, pk.ch_pk, m.m, h.h_1, r.r_1) && pp.CHScheme.Verify(pp.ch_pp, h.ch_pk, m.m, h.h_2, r.r_2);
    }

    @Override
    public final void Collision(Randomness r_p, PublicParam pp, PublicKey pk, SecretKey sk, Message m, ETrapdoor etd, HashValue h, Randomness r, Message m_p) {
        if(!Verify(pp, pk, m, h, r)) throw new RuntimeException("校验失败");
        pp.CHScheme.Collision(r_p.r_1, pp.ch_pp, pk.ch_pk, sk.ch_sk, m.m, h.h_1, r.r_1, m_p.m);
        pp.CHScheme.Collision(r_p.r_2, pp.ch_pp, h.ch_pk, etd.ch_sk, m.m, h.h_2, r.r_2, m_p.m);
    }
}

