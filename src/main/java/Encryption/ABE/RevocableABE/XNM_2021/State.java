package Encryption.ABE.RevocableABE.XNM_2021;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

import java.util.BitSet;
import java.util.HashMap;
import java.util.Map;

public class State extends Encryption.ABE.RevocableABE.Components.State {
    private int empty_leaf_id;
    private HashMap<User, Integer> id_2_node;
    public MultivePoint[] g_theta;
    public BitSet tag_g;
    public BitSet tag;

    public State(int n) {
        g_theta = new MultivePoint[2 * n - 1];
        tag_g = new BitSet(2 * n - 1);
        tag = new BitSet(2 * n - 1);
        empty_leaf_id = n - 1;
        id_2_node = new HashMap<>();
    }

    public int GetFNodeId(int id) {
        return (id - 1) >> 1;
    }

    public int Pick(User user) {
        if(!id_2_node.containsKey(user)) {
            if(empty_leaf_id == g_theta.length) throw new RuntimeException("用户容量已满");
            id_2_node.put(user, empty_leaf_id);
            ++empty_leaf_id;
        }
        return id_2_node.get(user);
    }

    public void Setg(int node_id, MultivePoint g) {
        tag_g.set(node_id);
        g_theta[node_id] = g;
    }

    public void GetUpdateKeyNode(Revocated rl, Info info) {
        tag.set(0, g_theta.length);
        for(Map.Entry<User, Integer> e : rl.revocated.entrySet()) {
            if(e.getValue() <= info.timestamp && id_2_node.containsKey(e.getKey())) {
                int node_id = id_2_node.get(e.getKey());
                tag.set(node_id, false);
                while(node_id != 0) {
                    node_id = GetFNodeId(node_id);
                    tag.set(node_id, false);
                }
            }
        }
        for(int i = g_theta.length - 1; i > 0; --i) if(tag.get(GetFNodeId(i))) tag.set(i, false);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
