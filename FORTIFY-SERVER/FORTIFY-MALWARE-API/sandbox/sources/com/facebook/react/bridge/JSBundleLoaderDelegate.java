package com.facebook.react.bridge;

import android.content.res.AssetManager;
import kotlin.Metadata;

/* compiled from: JSBundleLoaderDelegate.kt */
@Metadata(d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u000b\n\u0002\b\b\bf\u0018\u00002\u00020\u0001J \u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\tH&J \u0010\n\u001a\u00020\u00032\u0006\u0010\u000b\u001a\u00020\u00072\u0006\u0010\f\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\tH&J\u0018\u0010\r\u001a\u00020\u00032\u0006\u0010\u000b\u001a\u00020\u00072\u0006\u0010\f\u001a\u00020\u0007H&J\u0018\u0010\u000e\u001a\u00020\u00032\u0006\u0010\u000f\u001a\u00020\u00072\u0006\u0010\u0010\u001a\u00020\u0007H&ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\u0011À\u0006\u0001"}, d2 = {"Lcom/facebook/react/bridge/JSBundleLoaderDelegate;", "", "loadScriptFromAssets", "", "assetManager", "Landroid/content/res/AssetManager;", "assetURL", "", "loadSynchronously", "", "loadScriptFromFile", "fileName", "sourceURL", "loadSplitBundleFromFile", "setSourceURLs", "deviceURL", "remoteURL", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface JSBundleLoaderDelegate {
    void loadScriptFromAssets(AssetManager assetManager, String assetURL, boolean loadSynchronously);

    void loadScriptFromFile(String fileName, String sourceURL, boolean loadSynchronously);

    void loadSplitBundleFromFile(String fileName, String sourceURL);

    void setSourceURLs(String deviceURL, String remoteURL);
}
