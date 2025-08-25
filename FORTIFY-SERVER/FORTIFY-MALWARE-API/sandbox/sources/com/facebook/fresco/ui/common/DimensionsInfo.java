package com.facebook.fresco.ui.common;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: DimensionsInfo.kt */
@Metadata(d1 = {"\u0000\"\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\b\n\u0002\b\u0006\n\u0002\u0010\u000e\n\u0002\b\f\n\u0002\u0010\u000b\n\u0002\b\f\b\u0086\b\u0018\u00002\u00020\u0001B?\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u0012\u0006\u0010\u0005\u001a\u00020\u0003\u0012\u0006\u0010\u0006\u001a\u00020\u0003\u0012\u0006\u0010\u0007\u001a\u00020\u0003\u0012\u0006\u0010\b\u001a\u00020\u0003\u0012\u0006\u0010\t\u001a\u00020\n¢\u0006\u0004\b\u000b\u0010\fJ\u0013\u0010\u0016\u001a\u00020\u00172\b\u0010\u0018\u001a\u0004\u0018\u00010\u0001H\u0096\u0002J\b\u0010\u0019\u001a\u00020\u0003H\u0016J\t\u0010\u001a\u001a\u00020\u0003HÆ\u0003J\t\u0010\u001b\u001a\u00020\u0003HÆ\u0003J\t\u0010\u001c\u001a\u00020\u0003HÆ\u0003J\t\u0010\u001d\u001a\u00020\u0003HÆ\u0003J\t\u0010\u001e\u001a\u00020\u0003HÆ\u0003J\t\u0010\u001f\u001a\u00020\u0003HÆ\u0003J\t\u0010 \u001a\u00020\nHÆ\u0003JO\u0010!\u001a\u00020\u00002\b\b\u0002\u0010\u0002\u001a\u00020\u00032\b\b\u0002\u0010\u0004\u001a\u00020\u00032\b\b\u0002\u0010\u0005\u001a\u00020\u00032\b\b\u0002\u0010\u0006\u001a\u00020\u00032\b\b\u0002\u0010\u0007\u001a\u00020\u00032\b\b\u0002\u0010\b\u001a\u00020\u00032\b\b\u0002\u0010\t\u001a\u00020\nHÆ\u0001J\t\u0010\"\u001a\u00020\nHÖ\u0001R\u0011\u0010\u0002\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\r\u0010\u000eR\u0011\u0010\u0004\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\u000f\u0010\u000eR\u0011\u0010\u0005\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\u0010\u0010\u000eR\u0011\u0010\u0006\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\u0011\u0010\u000eR\u0011\u0010\u0007\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\u0012\u0010\u000eR\u0011\u0010\b\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\u0013\u0010\u000eR\u0011\u0010\t\u001a\u00020\n¢\u0006\b\n\u0000\u001a\u0004\b\u0014\u0010\u0015¨\u0006#"}, d2 = {"Lcom/facebook/fresco/ui/common/DimensionsInfo;", "", "viewportWidth", "", "viewportHeight", "encodedImageWidth", "encodedImageHeight", "decodedImageWidth", "decodedImageHeight", "scaleType", "", "<init>", "(IIIIIILjava/lang/String;)V", "getViewportWidth", "()I", "getViewportHeight", "getEncodedImageWidth", "getEncodedImageHeight", "getDecodedImageWidth", "getDecodedImageHeight", "getScaleType", "()Ljava/lang/String;", "equals", "", "other", "hashCode", "component1", "component2", "component3", "component4", "component5", "component6", "component7", "copy", "toString", "ui-common_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final /* data */ class DimensionsInfo {
    private final int decodedImageHeight;
    private final int decodedImageWidth;
    private final int encodedImageHeight;
    private final int encodedImageWidth;
    private final String scaleType;
    private final int viewportHeight;
    private final int viewportWidth;

    public static /* synthetic */ DimensionsInfo copy$default(DimensionsInfo dimensionsInfo, int i, int i2, int i3, int i4, int i5, int i6, String str, int i7, Object obj) {
        if ((i7 & 1) != 0) {
            i = dimensionsInfo.viewportWidth;
        }
        if ((i7 & 2) != 0) {
            i2 = dimensionsInfo.viewportHeight;
        }
        int i8 = i2;
        if ((i7 & 4) != 0) {
            i3 = dimensionsInfo.encodedImageWidth;
        }
        int i9 = i3;
        if ((i7 & 8) != 0) {
            i4 = dimensionsInfo.encodedImageHeight;
        }
        int i10 = i4;
        if ((i7 & 16) != 0) {
            i5 = dimensionsInfo.decodedImageWidth;
        }
        int i11 = i5;
        if ((i7 & 32) != 0) {
            i6 = dimensionsInfo.decodedImageHeight;
        }
        int i12 = i6;
        if ((i7 & 64) != 0) {
            str = dimensionsInfo.scaleType;
        }
        return dimensionsInfo.copy(i, i8, i9, i10, i11, i12, str);
    }

    /* renamed from: component1, reason: from getter */
    public final int getViewportWidth() {
        return this.viewportWidth;
    }

    /* renamed from: component2, reason: from getter */
    public final int getViewportHeight() {
        return this.viewportHeight;
    }

    /* renamed from: component3, reason: from getter */
    public final int getEncodedImageWidth() {
        return this.encodedImageWidth;
    }

    /* renamed from: component4, reason: from getter */
    public final int getEncodedImageHeight() {
        return this.encodedImageHeight;
    }

    /* renamed from: component5, reason: from getter */
    public final int getDecodedImageWidth() {
        return this.decodedImageWidth;
    }

    /* renamed from: component6, reason: from getter */
    public final int getDecodedImageHeight() {
        return this.decodedImageHeight;
    }

    /* renamed from: component7, reason: from getter */
    public final String getScaleType() {
        return this.scaleType;
    }

    public final DimensionsInfo copy(int viewportWidth, int viewportHeight, int encodedImageWidth, int encodedImageHeight, int decodedImageWidth, int decodedImageHeight, String scaleType) {
        Intrinsics.checkNotNullParameter(scaleType, "scaleType");
        return new DimensionsInfo(viewportWidth, viewportHeight, encodedImageWidth, encodedImageHeight, decodedImageWidth, decodedImageHeight, scaleType);
    }

    public String toString() {
        return "DimensionsInfo(viewportWidth=" + this.viewportWidth + ", viewportHeight=" + this.viewportHeight + ", encodedImageWidth=" + this.encodedImageWidth + ", encodedImageHeight=" + this.encodedImageHeight + ", decodedImageWidth=" + this.decodedImageWidth + ", decodedImageHeight=" + this.decodedImageHeight + ", scaleType=" + this.scaleType + ")";
    }

    public DimensionsInfo(int i, int i2, int i3, int i4, int i5, int i6, String scaleType) {
        Intrinsics.checkNotNullParameter(scaleType, "scaleType");
        this.viewportWidth = i;
        this.viewportHeight = i2;
        this.encodedImageWidth = i3;
        this.encodedImageHeight = i4;
        this.decodedImageWidth = i5;
        this.decodedImageHeight = i6;
        this.scaleType = scaleType;
    }

    public final int getViewportWidth() {
        return this.viewportWidth;
    }

    public final int getViewportHeight() {
        return this.viewportHeight;
    }

    public final int getEncodedImageWidth() {
        return this.encodedImageWidth;
    }

    public final int getEncodedImageHeight() {
        return this.encodedImageHeight;
    }

    public final int getDecodedImageWidth() {
        return this.decodedImageWidth;
    }

    public final int getDecodedImageHeight() {
        return this.decodedImageHeight;
    }

    public final String getScaleType() {
        return this.scaleType;
    }

    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!Intrinsics.areEqual(getClass(), other != null ? other.getClass() : null)) {
            return false;
        }
        Intrinsics.checkNotNull(other, "null cannot be cast to non-null type com.facebook.fresco.ui.common.DimensionsInfo");
        DimensionsInfo dimensionsInfo = (DimensionsInfo) other;
        return this.viewportWidth == dimensionsInfo.viewportWidth && this.viewportHeight == dimensionsInfo.viewportHeight && this.encodedImageWidth == dimensionsInfo.encodedImageWidth && this.encodedImageHeight == dimensionsInfo.encodedImageHeight && this.decodedImageWidth == dimensionsInfo.decodedImageWidth && this.decodedImageHeight == dimensionsInfo.decodedImageHeight && Intrinsics.areEqual(this.scaleType, dimensionsInfo.scaleType);
    }

    public int hashCode() {
        return (((((((((((this.viewportWidth * 31) + this.viewportHeight) * 31) + this.encodedImageWidth) * 31) + this.encodedImageHeight) * 31) + this.decodedImageWidth) * 31) + this.decodedImageHeight) * 31) + this.scaleType.hashCode();
    }
}
