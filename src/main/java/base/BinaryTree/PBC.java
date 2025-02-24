package base.BinaryTree;

import it.unisa.dia.gas.jpbc.Element;

import java.util.BitSet;
import java.util.HashMap;

/*
 * Identity-based Encryption with Efficient Revocation
 * P5
 */

public class PBC {
    public static class RevokeList {
        public HashMap<Element, Integer> rl = new HashMap<>();

        public void Add(Element id, int expire_time) {
            if(!rl.containsKey(id) || (rl.containsKey(id) && rl.get(id) >= expire_time)) rl.put(id, expire_time);
        }
    }

    private int empty_leaf_id;
    private final HashMap<Element, Integer> id_2_node = new HashMap<>();
    public Element[] g_theta;
    public BitSet tag_g;
    public BitSet tag;

    public PBC(int n) {
        g_theta = new Element[2 * n - 1];
        tag_g = new BitSet(2 * n - 1);
        tag = new BitSet(2 * n - 1);
        empty_leaf_id = n - 1;
    }

    public int GetFNodeId(int id) {
        return (id - 1) >> 1;
    }

    public int Pick(Element id) {
        if(!id_2_node.containsKey(id)) {
            if(empty_leaf_id == g_theta.length) throw new RuntimeException("binary tree is full");
            id_2_node.put(id, empty_leaf_id);
            ++empty_leaf_id;
        }
        return id_2_node.get(id);
    }

    public void Setg(int node_id, Element g) {
        tag_g.set(node_id);
        g_theta[node_id] = g;
    }

    public void GetUpdateKeyNode(RevokeList RL, int time) {
        tag.set(0, g_theta.length);
        for(Element id : RL.rl.keySet()) {
            if(RL.rl.get(id) <= time && id_2_node.containsKey(id)) {
                int node_id = id_2_node.get(id);
                tag.set(node_id, false);
                while(node_id != 0) {
                    node_id = GetFNodeId(node_id);
                    tag.set(node_id, false);
                }
            }
        }
        for(int i = g_theta.length - 1; i > 0; --i) if(tag.get(GetFNodeId(i))) tag.set(i, false);
    }

    public void Print() {
        int h = 1;
        while(g_theta.length > h) h <<= 1;
        System.out.println(h);
        int id = 0, i = 1;
        while(id < g_theta.length) {
            System.out.print(" ".repeat((h >> 1) - 1));
            for(int j = 0;j < i;++j) {
                if(id == g_theta.length) break;
                System.out.print((tag.get(id) ? 1 : 0) + " ".repeat(h - 1));
                ++id;
            }
            System.out.println();
            i <<= 1;
            h >>= 1;
        }
        System.out.println("done print BT\n");
    }

    public void PrintTheta() {
        int h = 1;
        while(g_theta.length > h) h <<= 1;
        System.out.println(h);
        int id = 0, i = 1;
        while(id < g_theta.length) {
            System.out.print(" ".repeat((h >> 1) - 1));
            for(int j = 0;j < i;++j) {
                if(id == g_theta.length) break;
                System.out.print((tag_g.get(id) ? 1 : 0) + " ".repeat(h - 1));
                ++id;
            }
            System.out.println();
            i <<= 1;
            h >>= 1;
        }
        System.out.println("done print BT\n");
    }
}
