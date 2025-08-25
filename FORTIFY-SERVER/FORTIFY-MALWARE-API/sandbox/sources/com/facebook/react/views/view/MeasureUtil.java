package com.facebook.react.views.view;

import android.view.View;
import androidx.constraintlayout.solver.widgets.analyzer.BasicMeasure;
import com.facebook.yoga.YogaMeasureMode;
import kotlin.Metadata;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: MeasureUtil.kt */
@Metadata(d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0007\n\u0000\n\u0002\u0018\u0002\n\u0000\bÆ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\u0018\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\tH\u0007¨\u0006\n"}, d2 = {"Lcom/facebook/react/views/view/MeasureUtil;", "", "<init>", "()V", "getMeasureSpec", "", "size", "", "mode", "Lcom/facebook/yoga/YogaMeasureMode;", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class MeasureUtil {
    public static final MeasureUtil INSTANCE = new MeasureUtil();

    /* compiled from: MeasureUtil.kt */
    @Metadata(k = 3, mv = {2, 0, 0}, xi = 48)
    public /* synthetic */ class WhenMappings {
        public static final /* synthetic */ int[] $EnumSwitchMapping$0;

        static {
            int[] iArr = new int[YogaMeasureMode.values().length];
            try {
                iArr[YogaMeasureMode.EXACTLY.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                iArr[YogaMeasureMode.AT_MOST.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            $EnumSwitchMapping$0 = iArr;
        }
    }

    private MeasureUtil() {
    }

    @JvmStatic
    public static final int getMeasureSpec(float size, YogaMeasureMode mode) {
        Intrinsics.checkNotNullParameter(mode, "mode");
        int i = WhenMappings.$EnumSwitchMapping$0[mode.ordinal()];
        if (i == 1) {
            return View.MeasureSpec.makeMeasureSpec((int) size, BasicMeasure.EXACTLY);
        }
        if (i == 2) {
            return View.MeasureSpec.makeMeasureSpec((int) size, Integer.MIN_VALUE);
        }
        return View.MeasureSpec.makeMeasureSpec(0, 0);
    }
}
