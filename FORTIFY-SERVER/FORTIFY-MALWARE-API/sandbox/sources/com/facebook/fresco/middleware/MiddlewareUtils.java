package com.facebook.fresco.middleware;

import android.graphics.PointF;
import android.graphics.Rect;
import android.net.Uri;
import com.facebook.fresco.ui.common.ControllerListener2;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: MiddlewareUtils.kt */
@Metadata(d1 = {"\u0000:\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010$\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0000\bÆ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J®\u0001\u0010\u0004\u001a\u00020\u00052\u0012\u0010\u0006\u001a\u000e\u0012\u0004\u0012\u00020\b\u0012\u0004\u0012\u00020\u00010\u00072\u0012\u0010\t\u001a\u000e\u0012\u0004\u0012\u00020\b\u0012\u0004\u0012\u00020\u00010\u00072\u0014\u0010\n\u001a\u0010\u0012\u0004\u0012\u00020\b\u0012\u0004\u0012\u00020\u0001\u0018\u00010\u00072\u0014\u0010\u000b\u001a\u0010\u0012\u0004\u0012\u00020\b\u0012\u0004\u0012\u00020\u0001\u0018\u00010\u00072\b\u0010\f\u001a\u0004\u0018\u00010\r2\b\u0010\u000e\u001a\u0004\u0018\u00010\b2\b\u0010\u000f\u001a\u0004\u0018\u00010\u00102\u0014\u0010\u0011\u001a\u0010\u0012\u0004\u0012\u00020\b\u0012\u0004\u0012\u00020\u0001\u0018\u00010\u00072\b\u0010\u0012\u001a\u0004\u0018\u00010\u00012\b\b\u0002\u0010\u0013\u001a\u00020\u00142\b\u0010\u0015\u001a\u0004\u0018\u00010\u0016H\u0007¨\u0006\u0017"}, d2 = {"Lcom/facebook/fresco/middleware/MiddlewareUtils;", "", "<init>", "()V", "obtainExtras", "Lcom/facebook/fresco/ui/common/ControllerListener2$Extras;", "componentAttribution", "", "", "shortcutAttribution", "dataSourceExtras", "imageSourceExtras", "viewportDimensions", "Landroid/graphics/Rect;", "scaleType", "focusPoint", "Landroid/graphics/PointF;", "imageExtras", "callerContext", "logWithHighSamplingRate", "", "mainUri", "Landroid/net/Uri;", "middleware_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class MiddlewareUtils {
    public static final MiddlewareUtils INSTANCE = new MiddlewareUtils();

    private MiddlewareUtils() {
    }

    @JvmStatic
    public static final ControllerListener2.Extras obtainExtras(Map<String, ? extends Object> componentAttribution, Map<String, ? extends Object> shortcutAttribution, Map<String, ? extends Object> dataSourceExtras, Map<String, ? extends Object> imageSourceExtras, Rect viewportDimensions, String scaleType, PointF focusPoint, Map<String, ? extends Object> imageExtras, Object callerContext, boolean logWithHighSamplingRate, Uri mainUri) {
        Intrinsics.checkNotNullParameter(componentAttribution, "componentAttribution");
        Intrinsics.checkNotNullParameter(shortcutAttribution, "shortcutAttribution");
        ControllerListener2.Extras extras = new ControllerListener2.Extras();
        if (viewportDimensions != null) {
            extras.viewportWidth = viewportDimensions.width();
            extras.viewportHeight = viewportDimensions.height();
        }
        extras.scaleType = scaleType;
        if (focusPoint != null) {
            extras.focusX = Float.valueOf(focusPoint.x);
            extras.focusY = Float.valueOf(focusPoint.y);
        }
        extras.callerContext = callerContext;
        extras.logWithHighSamplingRate = logWithHighSamplingRate;
        extras.mainUri = mainUri;
        extras.datasourceExtras = dataSourceExtras;
        extras.imageExtras = imageExtras;
        extras.shortcutExtras = shortcutAttribution;
        extras.componentExtras = componentAttribution;
        extras.imageSourceExtras = imageSourceExtras;
        return extras;
    }
}
