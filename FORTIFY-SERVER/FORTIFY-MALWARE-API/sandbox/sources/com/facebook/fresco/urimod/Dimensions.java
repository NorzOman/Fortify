package com.facebook.fresco.urimod;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: Dimensions.kt */
@Metadata(d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\b\n\u0002\b\u0007\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0006\b\u0086\b\u0018\u00002\u00020\u0001B\u0017\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0003¢\u0006\u0004\b\u0005\u0010\u0006J\b\u0010\n\u001a\u00020\u000bH\u0016J\u0013\u0010\f\u001a\u00020\r2\b\u0010\u000e\u001a\u0004\u0018\u00010\u0001H\u0096\u0002J\b\u0010\u000f\u001a\u00020\u0003H\u0016J\t\u0010\u0010\u001a\u00020\u0003HÆ\u0003J\t\u0010\u0011\u001a\u00020\u0003HÆ\u0003J\u001d\u0010\u0012\u001a\u00020\u00002\b\b\u0002\u0010\u0002\u001a\u00020\u00032\b\b\u0002\u0010\u0004\u001a\u00020\u0003HÆ\u0001R\u0011\u0010\u0002\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\u0007\u0010\bR\u0011\u0010\u0004\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\t\u0010\b¨\u0006\u0013"}, d2 = {"Lcom/facebook/fresco/urimod/Dimensions;", "", "w", "", "h", "<init>", "(II)V", "getW", "()I", "getH", "toString", "", "equals", "", "other", "hashCode", "component1", "component2", "copy", "urimod_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final /* data */ class Dimensions {
    private final int h;
    private final int w;

    public static /* synthetic */ Dimensions copy$default(Dimensions dimensions, int i, int i2, int i3, Object obj) {
        if ((i3 & 1) != 0) {
            i = dimensions.w;
        }
        if ((i3 & 2) != 0) {
            i2 = dimensions.h;
        }
        return dimensions.copy(i, i2);
    }

    /* renamed from: component1, reason: from getter */
    public final int getW() {
        return this.w;
    }

    /* renamed from: component2, reason: from getter */
    public final int getH() {
        return this.h;
    }

    public final Dimensions copy(int w, int h) {
        return new Dimensions(w, h);
    }

    public Dimensions(int i, int i2) {
        this.w = i;
        this.h = i2;
    }

    public final int getH() {
        return this.h;
    }

    public final int getW() {
        return this.w;
    }

    public String toString() {
        return this.w + "x" + this.h;
    }

    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!Intrinsics.areEqual(getClass(), other != null ? other.getClass() : null)) {
            return false;
        }
        Intrinsics.checkNotNull(other, "null cannot be cast to non-null type com.facebook.fresco.urimod.Dimensions");
        Dimensions dimensions = (Dimensions) other;
        return this.w == dimensions.w && this.h == dimensions.h;
    }

    public int hashCode() {
        return (this.w * 31) + this.h;
    }
}
