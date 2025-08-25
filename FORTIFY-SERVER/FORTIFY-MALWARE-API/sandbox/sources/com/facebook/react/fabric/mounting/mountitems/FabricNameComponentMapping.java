package com.facebook.react.fabric.mounting.mountitems;

import com.facebook.react.views.image.ReactImageManager;
import com.facebook.react.views.modal.ReactModalHostManager;
import com.facebook.react.views.progressbar.ReactProgressBarViewManager;
import com.facebook.react.views.scroll.ReactScrollViewManager;
import com.facebook.react.views.text.ReactRawTextManager;
import com.facebook.react.views.text.ReactTextViewManager;
import java.util.Map;
import kotlin.Metadata;
import kotlin.TuplesKt;
import kotlin.collections.MapsKt;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: FabricNameComponentMapping.kt */
@Metadata(d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010$\n\u0002\u0010\u000e\n\u0002\b\u0003\bÀ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\u0010\u0010\u0007\u001a\u00020\u00062\u0006\u0010\b\u001a\u00020\u0006H\u0007R\u001a\u0010\u0004\u001a\u000e\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\u00060\u0005X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\t"}, d2 = {"Lcom/facebook/react/fabric/mounting/mountitems/FabricNameComponentMapping;", "", "<init>", "()V", "componentNames", "", "", "getFabricComponentName", "componentName", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class FabricNameComponentMapping {
    public static final FabricNameComponentMapping INSTANCE = new FabricNameComponentMapping();
    private static final Map<String, String> componentNames = MapsKt.mapOf(TuplesKt.to("View", "RCTView"), TuplesKt.to("Image", ReactImageManager.REACT_CLASS), TuplesKt.to("ScrollView", ReactScrollViewManager.REACT_CLASS), TuplesKt.to("Slider", "RCTSlider"), TuplesKt.to("ModalHostView", ReactModalHostManager.REACT_CLASS), TuplesKt.to("Paragraph", ReactTextViewManager.REACT_CLASS), TuplesKt.to("Text", ReactTextViewManager.REACT_CLASS), TuplesKt.to("RawText", ReactRawTextManager.REACT_CLASS), TuplesKt.to("ActivityIndicatorView", ReactProgressBarViewManager.REACT_CLASS), TuplesKt.to("ShimmeringView", "RKShimmeringView"), TuplesKt.to("TemplateView", "RCTTemplateView"), TuplesKt.to("AxialGradientView", "RCTAxialGradientView"), TuplesKt.to("Video", "RCTVideo"), TuplesKt.to("Map", "RCTMap"), TuplesKt.to("WebView", "RCTWebView"), TuplesKt.to("Keyframes", "RCTKeyframes"), TuplesKt.to("ImpressionTrackingView", "RCTImpressionTrackingView"));

    private FabricNameComponentMapping() {
    }

    @JvmStatic
    public static final String getFabricComponentName(String componentName) {
        Intrinsics.checkNotNullParameter(componentName, "componentName");
        String str = componentNames.get(componentName);
        return str == null ? componentName : str;
    }
}
