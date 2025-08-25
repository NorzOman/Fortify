package com.facebook.react.modules.core;

import android.view.Choreographer;
import kotlin.Deprecated;
import kotlin.Metadata;

/* compiled from: ChoreographerCompat.kt */
@Metadata(d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0004\b\u0016\u0018\u00002\u00020\u0001:\u0001\u0004B\u0007¢\u0006\u0004\b\u0002\u0010\u0003¨\u0006\u0005"}, d2 = {"Lcom/facebook/react/modules/core/ChoreographerCompat;", "", "<init>", "()V", "FrameCallback", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public class ChoreographerCompat {

    /* compiled from: ChoreographerCompat.kt */
    @Deprecated(message = "Use Choreographer.FrameCallback instead")
    @Metadata(d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\b'\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b\u0002\u0010\u0003¨\u0006\u0004"}, d2 = {"Lcom/facebook/react/modules/core/ChoreographerCompat$FrameCallback;", "Landroid/view/Choreographer$FrameCallback;", "<init>", "()V", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public static abstract class FrameCallback implements Choreographer.FrameCallback {
    }
}
