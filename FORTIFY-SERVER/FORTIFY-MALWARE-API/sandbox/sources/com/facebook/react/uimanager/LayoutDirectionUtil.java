package com.facebook.react.uimanager;

import com.facebook.yoga.YogaDirection;
import kotlin.Metadata;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: LayoutDirectionUtil.kt */
@Metadata(d1 = {"\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\bÀ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\u0010\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u0007H\u0007J\u0010\u0010\b\u001a\u00020\u00072\u0006\u0010\u0006\u001a\u00020\u0005H\u0007¨\u0006\t"}, d2 = {"Lcom/facebook/react/uimanager/LayoutDirectionUtil;", "", "<init>", "()V", "toAndroidFromYoga", "", "direction", "Lcom/facebook/yoga/YogaDirection;", "toYogaFromAndroid", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class LayoutDirectionUtil {
    public static final LayoutDirectionUtil INSTANCE = new LayoutDirectionUtil();

    /* compiled from: LayoutDirectionUtil.kt */
    @Metadata(k = 3, mv = {2, 0, 0}, xi = 48)
    public /* synthetic */ class WhenMappings {
        public static final /* synthetic */ int[] $EnumSwitchMapping$0;

        static {
            int[] iArr = new int[YogaDirection.values().length];
            try {
                iArr[YogaDirection.LTR.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                iArr[YogaDirection.RTL.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            $EnumSwitchMapping$0 = iArr;
        }
    }

    private LayoutDirectionUtil() {
    }

    @JvmStatic
    public static final int toAndroidFromYoga(YogaDirection direction) {
        Intrinsics.checkNotNullParameter(direction, "direction");
        int i = WhenMappings.$EnumSwitchMapping$0[direction.ordinal()];
        if (i != 1) {
            return i != 2 ? 2 : 1;
        }
        return 0;
    }

    @JvmStatic
    public static final YogaDirection toYogaFromAndroid(int direction) {
        if (direction == 0) {
            return YogaDirection.LTR;
        }
        if (direction == 1) {
            return YogaDirection.RTL;
        }
        return YogaDirection.INHERIT;
    }
}
