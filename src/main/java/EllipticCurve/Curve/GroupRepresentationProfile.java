package EllipticCurve.Curve;

import EllipticCurve.Point.PointRepresentation;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

public final class GroupRepresentationProfile {
    private final PointRepresentation g1;
    private final PointRepresentation g2;
    private final PointRepresentation gt;
    private final int mask;

    private GroupRepresentationProfile(
            PointRepresentation g1,
            PointRepresentation g2,
            PointRepresentation gt
    ) {
        this.g1 = Objects.requireNonNull(g1, "G1 表示不能为空");
        this.g2 = Objects.requireNonNull(g2, "G2 表示不能为空");
        this.gt = Objects.requireNonNull(gt, "GT 表示不能为空");
        this.mask = (isMultive(g1) ? 1 : 0)
                | (isMultive(g2) ? 2 : 0)
                | (isMultive(gt) ? 4 : 0);
    }

    public static GroupRepresentationProfile of(
            PointRepresentation g1,
            PointRepresentation g2,
            PointRepresentation gt
    ) {
        return new GroupRepresentationProfile(g1, g2, gt);
    }

    public static GroupRepresentationProfile uniform(PointRepresentation representation) {
        return new GroupRepresentationProfile(representation, representation, representation);
    }

    public static GroupRepresentationProfile fromMask(int mask) {
        if (mask < 0 || mask > 7) {
            throw new IllegalArgumentException("表示掩码必须在 0~7 之间: " + mask);
        }
        return new GroupRepresentationProfile(
                (mask & 1) == 0 ? PointRepresentation.ADDITIVE : PointRepresentation.MULTIVE,
                (mask & 2) == 0 ? PointRepresentation.ADDITIVE : PointRepresentation.MULTIVE,
                (mask & 4) == 0 ? PointRepresentation.ADDITIVE : PointRepresentation.MULTIVE
        );
    }

    public static List<GroupRepresentationProfile> all() {
        List<GroupRepresentationProfile> profiles = new ArrayList<>();
        for (int mask = 0; mask < 8; mask++) profiles.add(fromMask(mask));
        return Collections.unmodifiableList(profiles);
    }

    public PointRepresentation representation(CurveGroup group) {
        Objects.requireNonNull(group, "群类型不能为空");
        switch (group) {
            case G1:
                return g1;
            case G2:
                return g2;
            case GT:
                return gt;
            default:
                throw new IllegalArgumentException("未知群类型: " + group);
        }
    }

    public PointRepresentation g1() {
        return g1;
    }

    public PointRepresentation g2() {
        return g2;
    }

    public PointRepresentation gt() {
        return gt;
    }

    public int mask() {
        return mask;
    }

    @Override
    public String toString() {
        return "GroupRepresentationProfile{"
                + "G1=" + g1
                + ", G2=" + g2
                + ", GT=" + gt
                + ", mask=" + mask
                + '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof GroupRepresentationProfile)) return false;
        GroupRepresentationProfile that = (GroupRepresentationProfile) o;
        return g1 == that.g1 && g2 == that.g2 && gt == that.gt;
    }

    @Override
    public int hashCode() {
        return Objects.hash(g1, g2, gt);
    }

    private static boolean isMultive(PointRepresentation representation) {
        return representation == PointRepresentation.MULTIVE;
    }
}
