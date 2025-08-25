package com.facebook.react.uimanager;

import android.view.View;
import android.view.ViewGroup;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.UiThreadUtil;
import java.util.List;
import java.util.WeakHashMap;

/* loaded from: classes.dex */
public abstract class ViewGroupManager<T extends ViewGroup> extends BaseViewManager<T, LayoutShadowNode> implements IViewGroupManager<T> {
    private static WeakHashMap<View, Integer> mZIndexHash = new WeakHashMap<>();

    @Override // com.facebook.react.uimanager.IViewManagerWithChildren
    public boolean needsCustomLayoutForChildren() {
        return false;
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public void updateExtraData(T t, Object obj) {
    }

    public ViewGroupManager() {
        super(null);
    }

    public ViewGroupManager(ReactApplicationContext reactApplicationContext) {
        super(reactApplicationContext);
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public LayoutShadowNode createShadowNodeInstance() {
        return new LayoutShadowNode();
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public Class<? extends LayoutShadowNode> getShadowNodeClass() {
        return LayoutShadowNode.class;
    }

    @Override // com.facebook.react.uimanager.IViewGroupManager
    public void addView(T t, View view, int i) {
        t.addView(view, i);
    }

    public void addViews(T t, List<View> list) {
        UiThreadUtil.assertOnUiThread();
        int size = list.size();
        for (int i = 0; i < size; i++) {
            addView((ViewGroupManager<T>) t, list.get(i), i);
        }
    }

    public static void setViewZIndex(View view, int i) {
        mZIndexHash.put(view, Integer.valueOf(i));
    }

    public static Integer getViewZIndex(View view) {
        return mZIndexHash.get(view);
    }

    @Override // com.facebook.react.uimanager.IViewGroupManager
    public int getChildCount(T t) {
        return t.getChildCount();
    }

    @Override // com.facebook.react.uimanager.IViewGroupManager
    public View getChildAt(T t, int i) {
        return t.getChildAt(i);
    }

    @Override // com.facebook.react.uimanager.IViewGroupManager
    public void removeViewAt(T t, int i) {
        UiThreadUtil.assertOnUiThread();
        t.removeViewAt(i);
    }

    public void removeView(T t, View view) {
        UiThreadUtil.assertOnUiThread();
        for (int i = 0; i < getChildCount((ViewGroupManager<T>) t); i++) {
            if (getChildAt((ViewGroupManager<T>) t, i) == view) {
                removeViewAt((ViewGroupManager<T>) t, i);
                return;
            }
        }
    }
}
