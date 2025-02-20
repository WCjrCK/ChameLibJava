package base.LSSS;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Queue;

/*
 * Decentralizing Attribute-Based Encryption
 * P30. G Converting from Boolean Formulas to LSSS Matrices
 */

public class Native {
    private enum TokenType {
        AND, OR, LEFT_BRACKET, RIGHT_BRACKET, TOKEN, POLICY
    }

    private static class Node {
        public int x;
        public short[] tag;
    }

    public static class Matrix {
        public short[][] M;

        public void Resize(int n, int m) {
            M = new short[n][m];
        }

        public void Print() {
            System.out.println("Matrix:");
            for (short[] shorts : M) {
                System.out.println(Arrays.toString(shorts));
            }
            System.out.println();
        }
    }

    public static class PolicyList {
        public String[] policy;

        public void Resize(int n) {
            policy = new String[n];
        }

        public void Print() {
            System.out.println("PolicyList:");
            System.out.println(Arrays.toString(policy));
            System.out.println();
        }
    }

    public void GenLSSSMatrices(Matrix M, PolicyList pi, String BooleanFormulas) {
        int n = 0, m = 1;
        int[][] range = new int[BooleanFormulas.length()][2];
        TokenType[] tokens = new TokenType[BooleanFormulas.length()];
        Queue<Integer> gates = new ArrayDeque<>();
        for(int i = 0; i < BooleanFormulas.length(); ++i) {
            range[i][0] = i;
            range[i][1] = i;
            switch (BooleanFormulas.charAt(i)) {
                case '&':
                    tokens[i] = TokenType.AND;
                    gates.add(i);
                    ++m;
                    break;

                case '|':
                    tokens[i] = TokenType.OR;
                    gates.add(i);
                    break;

                case '(':
                    tokens[i] = TokenType.LEFT_BRACKET;
                    break;

                case ')':
                    tokens[i] = TokenType.RIGHT_BRACKET;
                    break;

                default:
                    tokens[i] = TokenType.POLICY;
                    if(i == 0 || tokens[i - 1] != TokenType.POLICY) ++n;
                    else {
                        range[i][0] = range[i - 1][0];
                        range[range[i][0]][1] = i;
                    }
                    break;
            }
        }
        M.Resize(n, m);
        pi.Resize(n);
        int x = -1, L, R, loop_cnt = 0, row_cnt = 0;
        while(!gates.isEmpty()) {
            if(loop_cnt >= gates.size()) throw new RuntimeException("wrong boolean formulas");
            x = gates.poll();
            if((tokens[x - 1] != TokenType.TOKEN && tokens[x - 1] != TokenType.POLICY) || (tokens[x + 1] != TokenType.TOKEN && tokens[x + 1] != TokenType.POLICY)) {
                gates.add(x);
                ++loop_cnt;
                continue;
            }
            loop_cnt = 0;
            L = range[x - 1][0];
            if(tokens[L] == TokenType.POLICY && tokens[x - 1] == TokenType.POLICY) {
                pi.policy[row_cnt] = BooleanFormulas.substring(L, x);
                range[x][0] = -row_cnt;
                ++row_cnt;
                tokens[L] = TokenType.TOKEN;
                tokens[x - 1] = TokenType.TOKEN;
            } else range[x][0] = range[x - 1][1];
            R = range[x + 1][1];
            if(tokens[R] == TokenType.POLICY && tokens[x + 1] == TokenType.POLICY) {
                pi.policy[row_cnt] = BooleanFormulas.substring(x + 1, R + 1);
                range[x][1] = -row_cnt;
                ++row_cnt;
                tokens[R] = TokenType.TOKEN;
                tokens[x + 1] = TokenType.TOKEN;
            } else range[x][1] = range[x + 1][0];
            if(L > 0 && tokens[L - 1] == TokenType.LEFT_BRACKET) {
                --L;
                tokens[L] = TokenType.TOKEN;
                if(R < BooleanFormulas.length() - 1 && tokens[R + 1] == TokenType.RIGHT_BRACKET) {
                    ++R;
                    tokens[R] = TokenType.TOKEN;
                } else throw new RuntimeException("wrong boolean formulas");
            }
            range[L][0] = x;
            range[L][1] = R;
            range[R][0] = L;
            range[R][1] = x;
        }
        if(range[0][1] != BooleanFormulas.length() - 1 || range[BooleanFormulas.length() - 1][0] != 0) throw new RuntimeException("wrong boolean formulas");
        if(x == -1) {
            M.M[0][0] = 1;
            pi.policy[0] = BooleanFormulas;
        } else {
            Queue<Node> rt = new ArrayDeque<>();
            Node tmp = new Node();
            tmp.x = x;
            tmp.tag = new short[m];
            tmp.tag[0] = 1;
            rt.add(tmp);
            int col_cnt = 1;
            while(!rt.isEmpty()) {
                tmp = rt.poll();
                if(tokens[tmp.x] == TokenType.AND) {
                    if(range[tmp.x][0] < 1) {
                        if (col_cnt >= 0) System.arraycopy(tmp.tag, 0, M.M[-range[tmp.x][0]], 0, col_cnt);
                        M.M[-range[tmp.x][0]][col_cnt] = 1;
                    } else {
                        Node tmp_L = new Node();
                        tmp_L.x = range[tmp.x][0];
                        tmp_L.tag = new short[m];
                        if (col_cnt >= 0) System.arraycopy(tmp.tag, 0, tmp_L.tag, 0, col_cnt);
                        tmp_L.tag[col_cnt] = 1;
                        rt.add(tmp_L);
                    }
                    if(range[tmp.x][1] < 1) {
                        M.M[-range[tmp.x][1]][col_cnt] = -1;
                    } else {
                        Node tmp_R = new Node();
                        tmp_R.x = range[tmp.x][1];
                        tmp_R.tag = new short[m];
                        tmp_R.tag[col_cnt] = -1;
                        rt.add(tmp_R);
                    }
                    ++col_cnt;
                } else if (tokens[tmp.x] == TokenType.OR) {
                    if(range[tmp.x][0] < 1) {
                        if (col_cnt >= 0) System.arraycopy(tmp.tag, 0, M.M[-range[tmp.x][0]], 0, col_cnt);
                    } else {
                        Node tmp_L = new Node();
                        tmp_L.x = range[tmp.x][0];
                        tmp_L.tag = tmp.tag;
                        rt.add(tmp_L);
                    }
                    if(range[tmp.x][1] < 1) {
                        if (col_cnt >= 0) System.arraycopy(tmp.tag, 0, M.M[-range[tmp.x][1]], 0, col_cnt);
                    } else {
                        Node tmp_R = new Node();
                        tmp_R.x = range[tmp.x][1];
                        tmp_R.tag = tmp.tag;
                        rt.add(tmp_R);
                    }
                }
            }
        }
    }
}
