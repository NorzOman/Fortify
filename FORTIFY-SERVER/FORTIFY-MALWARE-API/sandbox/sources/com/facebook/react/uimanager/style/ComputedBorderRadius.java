package com.facebook.react.uimanager.style;

import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: ComputedBorderRadius.kt */
@Metadata(d1 = {"\u0000.\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\f\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u000e\n\u0000\b\u0086\b\u0018\u00002\u00020\u0001B'\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u0012\u0006\u0010\u0005\u001a\u00020\u0003\u0012\u0006\u0010\u0006\u001a\u00020\u0003¢\u0006\u0004\b\u0007\u0010\bB\t\b\u0016¢\u0006\u0004\b\u0007\u0010\tJ\u0006\u0010\u000f\u001a\u00020\u0010J\u0006\u0010\u0011\u001a\u00020\u0010J\u000e\u0010\u0012\u001a\u00020\u00032\u0006\u0010\u0013\u001a\u00020\u0014J\t\u0010\u0015\u001a\u00020\u0003HÆ\u0003J\t\u0010\u0016\u001a\u00020\u0003HÆ\u0003J\t\u0010\u0017\u001a\u00020\u0003HÆ\u0003J\t\u0010\u0018\u001a\u00020\u0003HÆ\u0003J1\u0010\u0019\u001a\u00020\u00002\b\b\u0002\u0010\u0002\u001a\u00020\u00032\b\b\u0002\u0010\u0004\u001a\u00020\u00032\b\b\u0002\u0010\u0005\u001a\u00020\u00032\b\b\u0002\u0010\u0006\u001a\u00020\u0003HÆ\u0001J\u0013\u0010\u001a\u001a\u00020\u00102\b\u0010\u001b\u001a\u0004\u0018\u00010\u0001HÖ\u0003J\t\u0010\u001c\u001a\u00020\u001dHÖ\u0001J\t\u0010\u001e\u001a\u00020\u001fHÖ\u0001R\u0011\u0010\u0002\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\n\u0010\u000bR\u0011\u0010\u0004\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\f\u0010\u000bR\u0011\u0010\u0005\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\r\u0010\u000bR\u0011\u0010\u0006\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\u000e\u0010\u000b¨\u0006 "}, d2 = {"Lcom/facebook/react/uimanager/style/ComputedBorderRadius;", "", "topLeft", "Lcom/facebook/react/uimanager/style/CornerRadii;", "topRight", "bottomLeft", "bottomRight", "<init>", "(Lcom/facebook/react/uimanager/style/CornerRadii;Lcom/facebook/react/uimanager/style/CornerRadii;Lcom/facebook/react/uimanager/style/CornerRadii;Lcom/facebook/react/uimanager/style/CornerRadii;)V", "()V", "getTopLeft", "()Lcom/facebook/react/uimanager/style/CornerRadii;", "getTopRight", "getBottomLeft", "getBottomRight", "hasRoundedBorders", "", "isUniform", "get", "property", "Lcom/facebook/react/uimanager/style/ComputedBorderRadiusProp;", "component1", "component2", "component3", "component4", "copy", "equals", "other", "hashCode", "", "toString", "", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final /* data */ class ComputedBorderRadius {
    private final CornerRadii bottomLeft;
    private final CornerRadii bottomRight;
    private final CornerRadii topLeft;
    private final CornerRadii topRight;

    /* compiled from: ComputedBorderRadius.kt */
    @Metadata(k = 3, mv = {2, 0, 0}, xi = 48)
    public /* synthetic */ class WhenMappings {
        public static final /* synthetic */ int[] $EnumSwitchMapping$0;

        static {
            int[] iArr = new int[ComputedBorderRadiusProp.values().length];
            try {
                iArr[ComputedBorderRadiusProp.COMPUTED_BORDER_TOP_LEFT_RADIUS.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                iArr[ComputedBorderRadiusProp.COMPUTED_BORDER_TOP_RIGHT_RADIUS.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                iArr[ComputedBorderRadiusProp.COMPUTED_BORDER_BOTTOM_LEFT_RADIUS.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                iArr[ComputedBorderRadiusProp.COMPUTED_BORDER_BOTTOM_RIGHT_RADIUS.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            $EnumSwitchMapping$0 = iArr;
        }
    }

    public static /* synthetic */ ComputedBorderRadius copy$default(ComputedBorderRadius computedBorderRadius, CornerRadii cornerRadii, CornerRadii cornerRadii2, CornerRadii cornerRadii3, CornerRadii cornerRadii4, int i, Object obj) {
        if ((i & 1) != 0) {
            cornerRadii = computedBorderRadius.topLeft;
        }
        if ((i & 2) != 0) {
            cornerRadii2 = computedBorderRadius.topRight;
        }
        if ((i & 4) != 0) {
            cornerRadii3 = computedBorderRadius.bottomLeft;
        }
        if ((i & 8) != 0) {
            cornerRadii4 = computedBorderRadius.bottomRight;
        }
        return computedBorderRadius.copy(cornerRadii, cornerRadii2, cornerRadii3, cornerRadii4);
    }

    /* renamed from: component1, reason: from getter */
    public final CornerRadii getTopLeft() {
        return this.topLeft;
    }

    /* renamed from: component2, reason: from getter */
    public final CornerRadii getTopRight() {
        return this.topRight;
    }

    /* renamed from: component3, reason: from getter */
    public final CornerRadii getBottomLeft() {
        return this.bottomLeft;
    }

    /* renamed from: component4, reason: from getter */
    public final CornerRadii getBottomRight() {
        return this.bottomRight;
    }

    public final ComputedBorderRadius copy(CornerRadii topLeft, CornerRadii topRight, CornerRadii bottomLeft, CornerRadii bottomRight) {
        Intrinsics.checkNotNullParameter(topLeft, "topLeft");
        Intrinsics.checkNotNullParameter(topRight, "topRight");
        Intrinsics.checkNotNullParameter(bottomLeft, "bottomLeft");
        Intrinsics.checkNotNullParameter(bottomRight, "bottomRight");
        return new ComputedBorderRadius(topLeft, topRight, bottomLeft, bottomRight);
    }

    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof ComputedBorderRadius)) {
            return false;
        }
        ComputedBorderRadius computedBorderRadius = (ComputedBorderRadius) other;
        return Intrinsics.areEqual(this.topLeft, computedBorderRadius.topLeft) && Intrinsics.areEqual(this.topRight, computedBorderRadius.topRight) && Intrinsics.areEqual(this.bottomLeft, computedBorderRadius.bottomLeft) && Intrinsics.areEqual(this.bottomRight, computedBorderRadius.bottomRight);
    }

    public int hashCode() {
        return (((((this.topLeft.hashCode() * 31) + this.topRight.hashCode()) * 31) + this.bottomLeft.hashCode()) * 31) + this.bottomRight.hashCode();
    }

    public String toString() {
        return "ComputedBorderRadius(topLeft=" + this.topLeft + ", topRight=" + this.topRight + ", bottomLeft=" + this.bottomLeft + ", bottomRight=" + this.bottomRight + ")";
    }

    public ComputedBorderRadius(CornerRadii topLeft, CornerRadii topRight, CornerRadii bottomLeft, CornerRadii bottomRight) {
        Intrinsics.checkNotNullParameter(topLeft, "topLeft");
        Intrinsics.checkNotNullParameter(topRight, "topRight");
        Intrinsics.checkNotNullParameter(bottomLeft, "bottomLeft");
        Intrinsics.checkNotNullParameter(bottomRight, "bottomRight");
        this.topLeft = topLeft;
        this.topRight = topRight;
        this.bottomLeft = bottomLeft;
        this.bottomRight = bottomRight;
    }

    public final CornerRadii getTopLeft() {
        return this.topLeft;
    }

    public final CornerRadii getTopRight() {
        return this.topRight;
    }

    public final CornerRadii getBottomLeft() {
        return this.bottomLeft;
    }

    public final CornerRadii getBottomRight() {
        return this.bottomRight;
    }

    public final boolean hasRoundedBorders() {
        return this.topLeft.getHorizontal() > 0.0f || this.topLeft.getVertical() > 0.0f || this.topRight.getHorizontal() > 0.0f || this.topRight.getVertical() > 0.0f || this.bottomLeft.getHorizontal() > 0.0f || this.bottomLeft.getVertical() > 0.0f || this.bottomRight.getHorizontal() > 0.0f;
    }

    public final boolean isUniform() {
        return Intrinsics.areEqual(this.topLeft, this.topRight) && Intrinsics.areEqual(this.topLeft, this.bottomLeft) && Intrinsics.areEqual(this.topLeft, this.bottomRight);
    }

    public final CornerRadii get(ComputedBorderRadiusProp property) {
        Intrinsics.checkNotNullParameter(property, "property");
        int i = WhenMappings.$EnumSwitchMapping$0[property.ordinal()];
        if (i == 1) {
            return this.topLeft;
        }
        if (i == 2) {
            return this.topRight;
        }
        if (i == 3) {
            return this.bottomLeft;
        }
        if (i != 4) {
            throw new NoWhenBranchMatchedException();
        }
        return this.bottomRight;
    }

    public ComputedBorderRadius() {
        this(new CornerRadii(0.0f, 0.0f), new CornerRadii(0.0f, 0.0f), new CornerRadii(0.0f, 0.0f), new CornerRadii(0.0f, 0.0f));
    }
}
