package com.facebook.react.uimanager.common;

import android.view.View;
import kotlin.Deprecated;
import kotlin.Metadata;
import kotlin.ReplaceWith;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: ViewUtil.kt */
@Metadata(d1 = {"\u0000\"\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0000\bÆ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\u0010\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0007\u001a\u00020\u0005H\u0007J\u0010\u0010\u0006\u001a\u00020\u00052\u0006\u0010\b\u001a\u00020\tH\u0007J\u0018\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0007\u001a\u00020\u00052\u0006\u0010\n\u001a\u00020\u0005H\u0007J\u0010\u0010\u000b\u001a\u00020\f2\u0006\u0010\u0007\u001a\u00020\u0005H\u0007R\u000e\u0010\u0004\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000¨\u0006\r"}, d2 = {"Lcom/facebook/react/uimanager/common/ViewUtil;", "", "<init>", "()V", "NO_SURFACE_ID", "", "getUIManagerType", "viewTag", "view", "Landroid/view/View;", "surfaceId", "isRootTag", "", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class ViewUtil {
    public static final ViewUtil INSTANCE = new ViewUtil();
    public static final int NO_SURFACE_ID = -1;

    private ViewUtil() {
    }

    @JvmStatic
    public static final int getUIManagerType(int viewTag) {
        return viewTag % 2 == 0 ? 2 : 1;
    }

    @JvmStatic
    public static final int getUIManagerType(View view) {
        Intrinsics.checkNotNullParameter(view, "view");
        return getUIManagerType(view.getId());
    }

    @JvmStatic
    public static final int getUIManagerType(int viewTag, int surfaceId) {
        int i = surfaceId == -1 ? 1 : 2;
        if (i == 1 && !isRootTag(viewTag) && viewTag % 2 == 0) {
            return 2;
        }
        return i;
    }

    @Deprecated(message = "You should not check the tag of the view to inspect if it's the rootTag. Relying on this logic could make your app/library break in the future.", replaceWith = @ReplaceWith(expression = "", imports = {}))
    @JvmStatic
    public static final boolean isRootTag(int viewTag) {
        return viewTag % 10 == 1;
    }
}
