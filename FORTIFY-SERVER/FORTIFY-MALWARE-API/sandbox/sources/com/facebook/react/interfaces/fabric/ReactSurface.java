package com.facebook.react.interfaces.fabric;

import android.content.Context;
import android.view.ViewGroup;
import com.facebook.react.interfaces.TaskInterface;
import com.facebook.react.uimanager.ViewProps;
import kotlin.Metadata;

/* compiled from: ReactSurface.kt */
@Metadata(d1 = {"\u0000F\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\b\u0002\bf\u0018\u00002\u00020\u0001J\u000e\u0010\u0015\u001a\b\u0012\u0004\u0012\u00020\u00170\u0016H&J\u000e\u0010\u0018\u001a\b\u0012\u0004\u0012\u00020\u00170\u0016H&J\u000e\u0010\u0019\u001a\b\u0012\u0004\u0012\u00020\u00170\u0016H&J\b\u0010\u001a\u001a\u00020\u001bH&J\b\u0010\u001c\u001a\u00020\u001bH&R\u0012\u0010\u0002\u001a\u00020\u0003X¦\u0004¢\u0006\u0006\u001a\u0004\b\u0004\u0010\u0005R\u0012\u0010\u0006\u001a\u00020\u0007X¦\u0004¢\u0006\u0006\u001a\u0004\b\b\u0010\tR\u0012\u0010\n\u001a\u00020\u000bX¦\u0004¢\u0006\u0006\u001a\u0004\b\n\u0010\fR\u0014\u0010\r\u001a\u0004\u0018\u00010\u000eX¦\u0004¢\u0006\u0006\u001a\u0004\b\u000f\u0010\u0010R\u0012\u0010\u0011\u001a\u00020\u0012X¦\u0004¢\u0006\u0006\u001a\u0004\b\u0013\u0010\u0014ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\u001dÀ\u0006\u0001"}, d2 = {"Lcom/facebook/react/interfaces/fabric/ReactSurface;", "", "surfaceID", "", "getSurfaceID", "()I", "moduleName", "", "getModuleName", "()Ljava/lang/String;", "isRunning", "", "()Z", "view", "Landroid/view/ViewGroup;", "getView", "()Landroid/view/ViewGroup;", "context", "Landroid/content/Context;", "getContext", "()Landroid/content/Context;", "prerender", "Lcom/facebook/react/interfaces/TaskInterface;", "Ljava/lang/Void;", ViewProps.START, "stop", "clear", "", "detach", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface ReactSurface {
    void clear();

    void detach();

    Context getContext();

    String getModuleName();

    int getSurfaceID();

    ViewGroup getView();

    boolean isRunning();

    TaskInterface<Void> prerender();

    TaskInterface<Void> start();

    TaskInterface<Void> stop();
}
