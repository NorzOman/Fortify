package com.facebook.react.views.common;

import android.content.Context;
import android.content.ContextWrapper;
import kotlin.Metadata;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: ContextUtils.kt */
@Metadata(d1 = {"\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\bÆ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J/\u0010\u0004\u001a\u0004\u0018\u0001H\u0005\"\u0004\b\u0000\u0010\u00052\b\u0010\u0006\u001a\u0004\u0018\u00010\u00072\u000e\u0010\b\u001a\n\u0012\u0006\b\u0001\u0012\u0002H\u00050\tH\u0007¢\u0006\u0002\u0010\n¨\u0006\u000b"}, d2 = {"Lcom/facebook/react/views/common/ContextUtils;", "", "<init>", "()V", "findContextOfType", "T", "context", "Landroid/content/Context;", "clazz", "Ljava/lang/Class;", "(Landroid/content/Context;Ljava/lang/Class;)Ljava/lang/Object;", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class ContextUtils {
    public static final ContextUtils INSTANCE = new ContextUtils();

    private ContextUtils() {
    }

    @JvmStatic
    public static final <T> T findContextOfType(Context context, Class<? extends T> clazz) {
        Context baseContext;
        Intrinsics.checkNotNullParameter(clazz, "clazz");
        while (!clazz.isInstance(context)) {
            if (!(context instanceof ContextWrapper) || context == (baseContext = ((ContextWrapper) context).getBaseContext())) {
                return null;
            }
            context = baseContext;
        }
        return (T) context;
    }
}
