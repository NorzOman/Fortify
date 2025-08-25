package com.facebook.react;

import android.content.ComponentCallbacks2;
import android.content.Context;
import android.content.res.Configuration;
import com.facebook.react.bridge.MemoryPressureListener;
import java.util.Iterator;
import java.util.concurrent.CopyOnWriteArrayList;

/* loaded from: classes.dex */
public class MemoryPressureRouter implements ComponentCallbacks2 {
    private final CopyOnWriteArrayList<MemoryPressureListener> mListeners = new CopyOnWriteArrayList<>();

    @Override // android.content.ComponentCallbacks
    public void onConfigurationChanged(Configuration configuration) {
    }

    @Override // android.content.ComponentCallbacks
    public void onLowMemory() {
    }

    public MemoryPressureRouter(Context context) {
        context.getApplicationContext().registerComponentCallbacks(this);
    }

    public void destroy(Context context) {
        context.getApplicationContext().unregisterComponentCallbacks(this);
    }

    public void addMemoryPressureListener(MemoryPressureListener memoryPressureListener) {
        if (this.mListeners.contains(memoryPressureListener)) {
            return;
        }
        this.mListeners.add(memoryPressureListener);
    }

    public void removeMemoryPressureListener(MemoryPressureListener memoryPressureListener) {
        this.mListeners.remove(memoryPressureListener);
    }

    @Override // android.content.ComponentCallbacks2
    public void onTrimMemory(int i) {
        dispatchMemoryPressure(i);
    }

    private void dispatchMemoryPressure(int i) {
        Iterator<MemoryPressureListener> it = this.mListeners.iterator();
        while (it.hasNext()) {
            it.next().handleMemoryPressure(i);
        }
    }
}
