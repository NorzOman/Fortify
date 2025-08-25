package com.facebook.react.fabric.mounting;

import android.view.View;
import com.facebook.react.uimanager.PixelUtil;
import com.facebook.yoga.YogaMeasureMode;
import kotlin.Metadata;
import kotlin.jvm.JvmStatic;

/* compiled from: LayoutMetricsConversions.kt */
@Metadata(d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\bf\u0018\u0000 \u00022\u00020\u0001:\u0001\u0002ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\u0003À\u0006\u0001"}, d2 = {"Lcom/facebook/react/fabric/mounting/LayoutMetricsConversions;", "", "Companion", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface LayoutMetricsConversions {

    /* renamed from: Companion, reason: from kotlin metadata */
    public static final Companion INSTANCE = Companion.$$INSTANCE;

    @JvmStatic
    static float getMaxSize(int i) {
        return INSTANCE.getMaxSize(i);
    }

    @JvmStatic
    static float getMinSize(int i) {
        return INSTANCE.getMinSize(i);
    }

    @JvmStatic
    static YogaMeasureMode getYogaMeasureMode(float f, float f2) {
        return INSTANCE.getYogaMeasureMode(f, f2);
    }

    @JvmStatic
    static float getYogaSize(float f, float f2) {
        return INSTANCE.getYogaSize(f, f2);
    }

    /* compiled from: LayoutMetricsConversions.kt */
    @Metadata(d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\u0007\n\u0000\n\u0002\u0010\b\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0000\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\u0010\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u0007H\u0007J\u0010\u0010\b\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u0007H\u0007J\u0018\u0010\t\u001a\u00020\u00052\u0006\u0010\n\u001a\u00020\u00052\u0006\u0010\u000b\u001a\u00020\u0005H\u0007J\u0018\u0010\f\u001a\u00020\r2\u0006\u0010\n\u001a\u00020\u00052\u0006\u0010\u000b\u001a\u00020\u0005H\u0007¨\u0006\u000e"}, d2 = {"Lcom/facebook/react/fabric/mounting/LayoutMetricsConversions$Companion;", "", "<init>", "()V", "getMinSize", "", "viewMeasureSpec", "", "getMaxSize", "getYogaSize", "minSize", "maxSize", "getYogaMeasureMode", "Lcom/facebook/yoga/YogaMeasureMode;", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public static final class Companion {
        static final /* synthetic */ Companion $$INSTANCE = new Companion();

        private Companion() {
        }

        @JvmStatic
        public final float getMinSize(int viewMeasureSpec) {
            int mode = View.MeasureSpec.getMode(viewMeasureSpec);
            int size = View.MeasureSpec.getSize(viewMeasureSpec);
            if (mode == 1073741824) {
                return size;
            }
            return 0.0f;
        }

        @JvmStatic
        public final float getMaxSize(int viewMeasureSpec) {
            int mode = View.MeasureSpec.getMode(viewMeasureSpec);
            int size = View.MeasureSpec.getSize(viewMeasureSpec);
            if (mode == 0) {
                return Float.POSITIVE_INFINITY;
            }
            return size;
        }

        @JvmStatic
        public final float getYogaSize(float minSize, float maxSize) {
            if (minSize == maxSize) {
                return PixelUtil.INSTANCE.dpToPx(maxSize);
            }
            if (Float.isInfinite(maxSize)) {
                return Float.POSITIVE_INFINITY;
            }
            return PixelUtil.INSTANCE.dpToPx(maxSize);
        }

        @JvmStatic
        public final YogaMeasureMode getYogaMeasureMode(float minSize, float maxSize) {
            if (minSize == maxSize) {
                return YogaMeasureMode.EXACTLY;
            }
            if (Float.isInfinite(maxSize)) {
                return YogaMeasureMode.UNDEFINED;
            }
            return YogaMeasureMode.AT_MOST;
        }
    }
}
