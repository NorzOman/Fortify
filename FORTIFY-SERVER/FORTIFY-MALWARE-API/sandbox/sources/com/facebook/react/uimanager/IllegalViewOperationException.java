package com.facebook.react.uimanager;

import android.view.View;
import androidx.core.app.NotificationCompat;
import com.facebook.react.bridge.JSApplicationCausedNativeException;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: IllegalViewOperationException.kt */
@Metadata(d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0003\n\u0002\b\u0003\b\u0016\u0018\u00002\u00020\u0001B\u0011\b\u0016\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005B#\b\u0016\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\b\u0010\u0006\u001a\u0004\u0018\u00010\u0007\u0012\u0006\u0010\b\u001a\u00020\t¢\u0006\u0004\b\u0004\u0010\nJ\b\u0010\u000b\u001a\u0004\u0018\u00010\u0007R\u0010\u0010\u0006\u001a\u0004\u0018\u00010\u0007X\u0082\u000e¢\u0006\u0002\n\u0000¨\u0006\f"}, d2 = {"Lcom/facebook/react/uimanager/IllegalViewOperationException;", "Lcom/facebook/react/bridge/JSApplicationCausedNativeException;", NotificationCompat.CATEGORY_MESSAGE, "", "<init>", "(Ljava/lang/String;)V", "view", "Landroid/view/View;", "cause", "", "(Ljava/lang/String;Landroid/view/View;Ljava/lang/Throwable;)V", "getView", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public class IllegalViewOperationException extends JSApplicationCausedNativeException {
    private View view;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public IllegalViewOperationException(String msg) {
        super(msg);
        Intrinsics.checkNotNullParameter(msg, "msg");
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public IllegalViewOperationException(String msg, View view, Throwable cause) {
        super(msg, cause);
        Intrinsics.checkNotNullParameter(msg, "msg");
        Intrinsics.checkNotNullParameter(cause, "cause");
        this.view = view;
    }

    public final View getView() {
        return this.view;
    }
}
