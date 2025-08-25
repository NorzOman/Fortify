package com.facebook.react.bridge;

import com.facebook.common.logging.FLog;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Stack;

/* loaded from: classes.dex */
public final class FallbackJSBundleLoader extends JSBundleLoader {
    static final String RECOVERABLE = "facebook::react::Recoverable";
    static final String TAG = "FallbackJSBundleLoader";
    private final ArrayList<Exception> mRecoveredErrors = new ArrayList<>();
    private final Stack<JSBundleLoader> mLoaders = new Stack<>();

    public FallbackJSBundleLoader(List<JSBundleLoader> list) {
        ListIterator<JSBundleLoader> listIterator = list.listIterator(list.size());
        while (listIterator.hasPrevious()) {
            this.mLoaders.push(listIterator.previous());
        }
    }

    @Override // com.facebook.react.bridge.JSBundleLoader
    public String loadScript(JSBundleLoaderDelegate jSBundleLoaderDelegate) throws Exception {
        while (true) {
            try {
                return getDelegateLoader().loadScript(jSBundleLoaderDelegate);
            } catch (Exception e) {
                if (e.getMessage() == null || !e.getMessage().startsWith(RECOVERABLE)) {
                    throw e;
                }
                this.mLoaders.pop();
                this.mRecoveredErrors.add(e);
                FLog.wtf(TAG, "Falling back from recoverable error", e);
            }
        }
        throw e;
    }

    private JSBundleLoader getDelegateLoader() {
        if (!this.mLoaders.empty()) {
            return this.mLoaders.peek();
        }
        RuntimeException runtimeException = new RuntimeException("No fallback options available");
        Iterator<Exception> it = this.mRecoveredErrors.iterator();
        Throwable cause = runtimeException;
        while (it.hasNext()) {
            cause.initCause(it.next());
            while (cause.getCause() != null) {
                cause = cause.getCause();
            }
        }
        throw runtimeException;
    }
}
