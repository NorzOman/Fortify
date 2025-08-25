package com.facebook.fresco.ui.common;

import android.net.Uri;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import kotlin.Metadata;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* compiled from: ControllerListener2.kt */
@Metadata(d1 = {"\u0000*\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0010\u0003\n\u0002\b\u0004\bf\u0018\u0000*\u0004\b\u0000\u0010\u00012\u00020\u0002:\u0001\u0015J$\u0010\u0003\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00020\u00062\b\u0010\u0007\u001a\u0004\u0018\u00010\u00022\b\u0010\b\u001a\u0004\u0018\u00010\tH&J)\u0010\n\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00020\u00062\b\u0010\u000b\u001a\u0004\u0018\u00018\u00002\b\u0010\b\u001a\u0004\u0018\u00010\tH&¢\u0006\u0002\u0010\fJ\u001f\u0010\r\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00020\u00062\b\u0010\u000b\u001a\u0004\u0018\u00018\u0000H&¢\u0006\u0002\u0010\u000eJ\u0010\u0010\u000f\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00020\u0006H&J$\u0010\u0010\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00020\u00062\b\u0010\u0011\u001a\u0004\u0018\u00010\u00122\b\u0010\b\u001a\u0004\u0018\u00010\tH&J\u001a\u0010\u0013\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00020\u00062\b\u0010\b\u001a\u0004\u0018\u00010\tH&J\u0012\u0010\u0014\u001a\u00020\u00042\b\u0010\u0007\u001a\u0004\u0018\u00010\u0002H&¨\u0006\u0016"}, d2 = {"Lcom/facebook/fresco/ui/common/ControllerListener2;", "INFO", "", "onSubmit", "", "id", "", "callerContext", "extraData", "Lcom/facebook/fresco/ui/common/ControllerListener2$Extras;", "onFinalImageSet", "imageInfo", "(Ljava/lang/String;Ljava/lang/Object;Lcom/facebook/fresco/ui/common/ControllerListener2$Extras;)V", "onIntermediateImageSet", "(Ljava/lang/String;Ljava/lang/Object;)V", "onIntermediateImageFailed", "onFailure", "throwable", "", "onRelease", "onEmptyEvent", "Extras", "ui-common_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface ControllerListener2<INFO> {
    void onEmptyEvent(Object callerContext);

    void onFailure(String id, Throwable throwable, Extras extraData);

    void onFinalImageSet(String id, INFO imageInfo, Extras extraData);

    void onIntermediateImageFailed(String id);

    void onIntermediateImageSet(String id, INFO imageInfo);

    void onRelease(String id, Extras extraData);

    void onSubmit(String id, Object callerContext, Extras extraData);

    /* compiled from: ControllerListener2.kt */
    @Metadata(d1 = {"\u00006\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010$\n\u0002\u0010\u000e\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0010\u0007\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\u0006\u0018\u0000 \u001c2\u00020\u0001:\u0001\u001cB\u0007¢\u0006\u0004\b\u0002\u0010\u0003J\u0006\u0010\u001b\u001a\u00020\u0000R \u0010\u0004\u001a\u0010\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\u0001\u0018\u00010\u00058\u0006@\u0006X\u0087\u000e¢\u0006\u0002\n\u0000R \u0010\u0007\u001a\u0010\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\u0001\u0018\u00010\u00058\u0006@\u0006X\u0087\u000e¢\u0006\u0002\n\u0000R \u0010\b\u001a\u0010\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\u0001\u0018\u00010\u00058\u0006@\u0006X\u0087\u000e¢\u0006\u0002\n\u0000R \u0010\t\u001a\u0010\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\u0001\u0018\u00010\u00058\u0006@\u0006X\u0087\u000e¢\u0006\u0002\n\u0000R \u0010\n\u001a\u0010\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\u0001\u0018\u00010\u00058\u0006@\u0006X\u0087\u000e¢\u0006\u0002\n\u0000R\u0014\u0010\u000b\u001a\u0004\u0018\u00010\u00018\u0006@\u0006X\u0087\u000e¢\u0006\u0002\n\u0000R\u0014\u0010\f\u001a\u0004\u0018\u00010\r8\u0006@\u0006X\u0087\u000e¢\u0006\u0002\n\u0000R\u0012\u0010\u000e\u001a\u00020\u000f8\u0006@\u0006X\u0087\u000e¢\u0006\u0002\n\u0000R\u0012\u0010\u0010\u001a\u00020\u000f8\u0006@\u0006X\u0087\u000e¢\u0006\u0002\n\u0000R\u0014\u0010\u0011\u001a\u0004\u0018\u00010\u00018\u0006@\u0006X\u0087\u000e¢\u0006\u0002\n\u0000R\u0016\u0010\u0012\u001a\u0004\u0018\u00010\u00138\u0006@\u0006X\u0087\u000e¢\u0006\u0004\n\u0002\u0010\u0014R\u0016\u0010\u0015\u001a\u0004\u0018\u00010\u00138\u0006@\u0006X\u0087\u000e¢\u0006\u0004\n\u0002\u0010\u0014R\u0012\u0010\u0016\u001a\u00020\u00178\u0006@\u0006X\u0087\u000e¢\u0006\u0002\n\u0000R\u0014\u0010\u0018\u001a\u0004\u0018\u00010\u00068\u0006@\u0006X\u0087\u000e¢\u0006\u0002\n\u0000R\u0014\u0010\u0019\u001a\u0004\u0018\u00010\r8\u0006@\u0006X\u0087\u000e¢\u0006\u0002\n\u0000R\u0014\u0010\u001a\u001a\u0004\u0018\u00010\u00068\u0006@\u0006X\u0087\u000e¢\u0006\u0002\n\u0000¨\u0006\u001d"}, d2 = {"Lcom/facebook/fresco/ui/common/ControllerListener2$Extras;", "", "<init>", "()V", "componentExtras", "", "", "shortcutExtras", "datasourceExtras", "imageExtras", "imageSourceExtras", "callerContext", "mainUri", "Landroid/net/Uri;", "viewportWidth", "", "viewportHeight", "scaleType", "focusX", "", "Ljava/lang/Float;", "focusY", "logWithHighSamplingRate", "", "modifiedUriStatus", "originalUri", "uiFramework", "makeExtrasCopy", "Companion", "ui-common_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public static final class Extras {

        /* renamed from: Companion, reason: from kotlin metadata */
        public static final Companion INSTANCE = new Companion(null);
        public Object callerContext;
        public Map<String, ? extends Object> componentExtras;
        public Map<String, ? extends Object> datasourceExtras;
        public Float focusX;
        public Float focusY;
        public Map<String, ? extends Object> imageExtras;
        public Map<String, ? extends Object> imageSourceExtras;
        public boolean logWithHighSamplingRate;
        public Uri mainUri;
        public String modifiedUriStatus;
        public Uri originalUri;
        public Object scaleType;
        public Map<String, ? extends Object> shortcutExtras;
        public String uiFramework;
        public int viewportWidth = -1;
        public int viewportHeight = -1;

        @JvmStatic
        public static final Extras of(Map<String, ? extends Object> map) {
            return INSTANCE.of(map);
        }

        public final Extras makeExtrasCopy() {
            Extras extras = new Extras();
            Companion companion = INSTANCE;
            extras.componentExtras = companion.copyMap(this.componentExtras);
            extras.shortcutExtras = companion.copyMap(this.shortcutExtras);
            extras.datasourceExtras = companion.copyMap(this.datasourceExtras);
            extras.imageExtras = companion.copyMap(this.imageExtras);
            extras.callerContext = this.callerContext;
            extras.mainUri = this.mainUri;
            extras.viewportWidth = this.viewportWidth;
            extras.viewportHeight = this.viewportHeight;
            extras.scaleType = this.scaleType;
            extras.focusX = this.focusX;
            extras.focusY = this.focusY;
            extras.uiFramework = this.uiFramework;
            return extras;
        }

        /* compiled from: ControllerListener2.kt */
        @Metadata(d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010$\n\u0002\u0010\u000e\n\u0002\b\u0003\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\u001e\u0010\u0004\u001a\u00020\u00052\u0014\u0010\u0006\u001a\u0010\u0012\u0004\u0012\u00020\b\u0012\u0004\u0012\u00020\u0001\u0018\u00010\u0007H\u0007J.\u0010\t\u001a\u0010\u0012\u0004\u0012\u00020\b\u0012\u0004\u0012\u00020\u0001\u0018\u00010\u00072\u0016\b\u0001\u0010\n\u001a\u0010\u0012\u0004\u0012\u00020\b\u0012\u0004\u0012\u00020\u0001\u0018\u00010\u0007H\u0002¨\u0006\u000b"}, d2 = {"Lcom/facebook/fresco/ui/common/ControllerListener2$Extras$Companion;", "", "<init>", "()V", "of", "Lcom/facebook/fresco/ui/common/ControllerListener2$Extras;", "componentExtras", "", "", "copyMap", "map", "ui-common_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
        public static final class Companion {
            public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
                this();
            }

            private Companion() {
            }

            @JvmStatic
            public final Extras of(Map<String, ? extends Object> componentExtras) {
                Extras extras = new Extras();
                extras.componentExtras = componentExtras;
                return extras;
            }

            /* JADX INFO: Access modifiers changed from: private */
            public final Map<String, Object> copyMap(Map<String, ? extends Object> map) {
                return map != null ? new ConcurrentHashMap(map) : null;
            }
        }
    }
}
