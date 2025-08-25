package com.facebook.react.internal;

import android.view.Choreographer;
import com.facebook.react.bridge.UiThreadUtil;
import com.facebook.react.internal.ChoreographerProvider;
import kotlin.Metadata;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: AndroidChoreographerProvider.kt */
@Metadata(d1 = {"\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\bÆ\u0002\u0018\u00002\u00020\u0001:\u0001\u0007B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\b\u0010\u0004\u001a\u00020\u0000H\u0007J\b\u0010\u0005\u001a\u00020\u0006H\u0016¨\u0006\b"}, d2 = {"Lcom/facebook/react/internal/AndroidChoreographerProvider;", "Lcom/facebook/react/internal/ChoreographerProvider;", "<init>", "()V", "getInstance", "getChoreographer", "Lcom/facebook/react/internal/ChoreographerProvider$Choreographer;", "AndroidChoreographer", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class AndroidChoreographerProvider implements ChoreographerProvider {
    public static final AndroidChoreographerProvider INSTANCE = new AndroidChoreographerProvider();

    private AndroidChoreographerProvider() {
    }

    /* compiled from: AndroidChoreographerProvider.kt */
    @Metadata(d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\b\u0002\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b\u0002\u0010\u0003J\u0010\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\tH\u0016J\u0010\u0010\n\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\tH\u0016R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u000b"}, d2 = {"Lcom/facebook/react/internal/AndroidChoreographerProvider$AndroidChoreographer;", "Lcom/facebook/react/internal/ChoreographerProvider$Choreographer;", "<init>", "()V", "instance", "Landroid/view/Choreographer;", "postFrameCallback", "", "callback", "Landroid/view/Choreographer$FrameCallback;", "removeFrameCallback", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    private static final class AndroidChoreographer implements ChoreographerProvider.Choreographer {
        private final Choreographer instance;

        public AndroidChoreographer() {
            Choreographer choreographer = Choreographer.getInstance();
            Intrinsics.checkNotNullExpressionValue(choreographer, "getInstance(...)");
            this.instance = choreographer;
        }

        @Override // com.facebook.react.internal.ChoreographerProvider.Choreographer
        public void postFrameCallback(Choreographer.FrameCallback callback) {
            Intrinsics.checkNotNullParameter(callback, "callback");
            this.instance.postFrameCallback(callback);
        }

        @Override // com.facebook.react.internal.ChoreographerProvider.Choreographer
        public void removeFrameCallback(Choreographer.FrameCallback callback) {
            Intrinsics.checkNotNullParameter(callback, "callback");
            this.instance.removeFrameCallback(callback);
        }
    }

    @JvmStatic
    public static final AndroidChoreographerProvider getInstance() {
        return INSTANCE;
    }

    @Override // com.facebook.react.internal.ChoreographerProvider
    public ChoreographerProvider.Choreographer getChoreographer() {
        UiThreadUtil.assertOnUiThread();
        return new AndroidChoreographer();
    }
}
