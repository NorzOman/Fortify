package com.facebook.react.views.image;

import android.graphics.Shader;
import com.facebook.common.logging.FLog;
import com.facebook.drawee.drawable.ScalingUtils;
import com.facebook.react.common.ReactConstants;
import kotlin.Metadata;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: ImageResizeMode.kt */
@Metadata(d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\bÆ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\u0012\u0010\u000b\u001a\u00020\f2\b\u0010\r\u001a\u0004\u0018\u00010\u0005H\u0007J\u0012\u0010\u000e\u001a\u00020\u000f2\b\u0010\r\u001a\u0004\u0018\u00010\u0005H\u0007J\b\u0010\u0010\u001a\u00020\fH\u0007J\b\u0010\u0011\u001a\u00020\u000fH\u0007R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082T¢\u0006\u0002\n\u0000R\u000e\u0010\u0006\u001a\u00020\u0005X\u0082T¢\u0006\u0002\n\u0000R\u000e\u0010\u0007\u001a\u00020\u0005X\u0082T¢\u0006\u0002\n\u0000R\u000e\u0010\b\u001a\u00020\u0005X\u0082T¢\u0006\u0002\n\u0000R\u000e\u0010\t\u001a\u00020\u0005X\u0082T¢\u0006\u0002\n\u0000R\u000e\u0010\n\u001a\u00020\u0005X\u0082T¢\u0006\u0002\n\u0000¨\u0006\u0012"}, d2 = {"Lcom/facebook/react/views/image/ImageResizeMode;", "", "<init>", "()V", "RESIZE_MODE_CONTAIN", "", "RESIZE_MODE_COVER", "RESIZE_MODE_STRETCH", "RESIZE_MODE_CENTER", "RESIZE_MODE_REPEAT", "RESIZE_MODE_NONE", "toScaleType", "Lcom/facebook/drawee/drawable/ScalingUtils$ScaleType;", "resizeModeValue", "toTileMode", "Landroid/graphics/Shader$TileMode;", "defaultValue", "defaultTileMode", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class ImageResizeMode {
    public static final ImageResizeMode INSTANCE = new ImageResizeMode();
    private static final String RESIZE_MODE_CENTER = "center";
    private static final String RESIZE_MODE_CONTAIN = "contain";
    private static final String RESIZE_MODE_COVER = "cover";
    private static final String RESIZE_MODE_NONE = "none";
    private static final String RESIZE_MODE_REPEAT = "repeat";
    private static final String RESIZE_MODE_STRETCH = "stretch";

    private ImageResizeMode() {
    }

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue
    java.lang.NullPointerException: Cannot invoke "java.util.List.iterator()" because the return value of "jadx.core.dex.visitors.regions.SwitchOverStringVisitor$SwitchData.getNewCases()" is null
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.restoreSwitchOverString(SwitchOverStringVisitor.java:109)
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.visitRegion(SwitchOverStringVisitor.java:66)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:77)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:82)
     */
    @JvmStatic
    public static final ScalingUtils.ScaleType toScaleType(String resizeModeValue) {
        if (resizeModeValue != null) {
            switch (resizeModeValue.hashCode()) {
                case -1881872635:
                    if (resizeModeValue.equals(RESIZE_MODE_STRETCH)) {
                        ScalingUtils.ScaleType FIT_XY = ScalingUtils.ScaleType.FIT_XY;
                        Intrinsics.checkNotNullExpressionValue(FIT_XY, "FIT_XY");
                        return FIT_XY;
                    }
                    break;
                case -1364013995:
                    if (resizeModeValue.equals(RESIZE_MODE_CENTER)) {
                        ScalingUtils.ScaleType CENTER_INSIDE = ScalingUtils.ScaleType.CENTER_INSIDE;
                        Intrinsics.checkNotNullExpressionValue(CENTER_INSIDE, "CENTER_INSIDE");
                        return CENTER_INSIDE;
                    }
                    break;
                case -934531685:
                    if (resizeModeValue.equals(RESIZE_MODE_REPEAT)) {
                        return ScaleTypeStartInside.INSTANCE.getINSTANCE();
                    }
                    break;
                case 3387192:
                    if (resizeModeValue.equals("none")) {
                        return ScaleTypeStartInside.INSTANCE.getINSTANCE();
                    }
                    break;
                case 94852023:
                    if (resizeModeValue.equals(RESIZE_MODE_COVER)) {
                        ScalingUtils.ScaleType CENTER_CROP = ScalingUtils.ScaleType.CENTER_CROP;
                        Intrinsics.checkNotNullExpressionValue(CENTER_CROP, "CENTER_CROP");
                        return CENTER_CROP;
                    }
                    break;
                case 951526612:
                    if (resizeModeValue.equals(RESIZE_MODE_CONTAIN)) {
                        ScalingUtils.ScaleType FIT_CENTER = ScalingUtils.ScaleType.FIT_CENTER;
                        Intrinsics.checkNotNullExpressionValue(FIT_CENTER, "FIT_CENTER");
                        return FIT_CENTER;
                    }
                    break;
            }
        }
        if (resizeModeValue != null) {
            FLog.w(ReactConstants.TAG, "Invalid resize mode: '" + resizeModeValue + "'");
        }
        return defaultValue();
    }

    @JvmStatic
    public static final Shader.TileMode toTileMode(String resizeModeValue) {
        if (Intrinsics.areEqual(RESIZE_MODE_CONTAIN, resizeModeValue) || Intrinsics.areEqual(RESIZE_MODE_COVER, resizeModeValue) || Intrinsics.areEqual(RESIZE_MODE_STRETCH, resizeModeValue) || Intrinsics.areEqual(RESIZE_MODE_CENTER, resizeModeValue) || Intrinsics.areEqual("none", resizeModeValue)) {
            return Shader.TileMode.CLAMP;
        }
        if (Intrinsics.areEqual(RESIZE_MODE_REPEAT, resizeModeValue)) {
            return Shader.TileMode.REPEAT;
        }
        if (resizeModeValue != null) {
            FLog.w(ReactConstants.TAG, "Invalid resize mode: '" + resizeModeValue + "'");
        }
        return defaultTileMode();
    }

    @JvmStatic
    public static final ScalingUtils.ScaleType defaultValue() {
        ScalingUtils.ScaleType CENTER_CROP = ScalingUtils.ScaleType.CENTER_CROP;
        Intrinsics.checkNotNullExpressionValue(CENTER_CROP, "CENTER_CROP");
        return CENTER_CROP;
    }

    @JvmStatic
    public static final Shader.TileMode defaultTileMode() {
        return Shader.TileMode.CLAMP;
    }
}
