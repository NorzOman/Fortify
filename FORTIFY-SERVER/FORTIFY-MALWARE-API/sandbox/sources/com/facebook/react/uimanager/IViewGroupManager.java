package com.facebook.react.uimanager;

import android.view.View;
import com.facebook.react.bridge.UiThreadUtil;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: IViewGroupManager.kt */
@Metadata(d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\n\bf\u0018\u0000*\b\b\u0000\u0010\u0001*\u00020\u00022\u00020\u0003J%\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00028\u00002\u0006\u0010\u0007\u001a\u00020\u00022\u0006\u0010\b\u001a\u00020\tH&¢\u0006\u0002\u0010\nJ\u001f\u0010\u000b\u001a\u0004\u0018\u00010\u00022\u0006\u0010\u0006\u001a\u00028\u00002\u0006\u0010\b\u001a\u00020\tH&¢\u0006\u0002\u0010\fJ\u001d\u0010\r\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00028\u00002\u0006\u0010\b\u001a\u00020\tH&¢\u0006\u0002\u0010\u000eJ\u0015\u0010\u000f\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00028\u0000H\u0016¢\u0006\u0002\u0010\u0010J\u0015\u0010\u0011\u001a\u00020\t2\u0006\u0010\u0006\u001a\u00028\u0000H&¢\u0006\u0002\u0010\u0012ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\u0013À\u0006\u0001"}, d2 = {"Lcom/facebook/react/uimanager/IViewGroupManager;", "T", "Landroid/view/View;", "Lcom/facebook/react/uimanager/IViewManagerWithChildren;", "addView", "", "parent", "child", "index", "", "(Landroid/view/View;Landroid/view/View;I)V", "getChildAt", "(Landroid/view/View;I)Landroid/view/View;", "removeViewAt", "(Landroid/view/View;I)V", "removeAllViews", "(Landroid/view/View;)V", "getChildCount", "(Landroid/view/View;)I", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface IViewGroupManager<T extends View> extends IViewManagerWithChildren {
    void addView(T parent, View child, int index);

    View getChildAt(T parent, int index);

    int getChildCount(T parent);

    void removeViewAt(T parent, int index);

    default void removeAllViews(T parent) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        UiThreadUtil.assertOnUiThread();
        int childCount = getChildCount(parent);
        while (true) {
            childCount--;
            if (-1 >= childCount) {
                return;
            } else {
                removeViewAt(parent, childCount);
            }
        }
    }
}
