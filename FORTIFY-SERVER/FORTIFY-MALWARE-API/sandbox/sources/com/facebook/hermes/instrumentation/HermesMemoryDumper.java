package com.facebook.hermes.instrumentation;

import kotlin.Metadata;

/* compiled from: HermesMemoryDumper.kt */
@Metadata(d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\bf\u0018\u00002\u00020\u0001J\b\u0010\u0002\u001a\u00020\u0003H&J\b\u0010\u0004\u001a\u00020\u0005H&J\b\u0010\u0006\u001a\u00020\u0005H&J\u0010\u0010\u0007\u001a\u00020\b2\u0006\u0010\t\u001a\u00020\u0005H&ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\nÀ\u0006\u0001"}, d2 = {"Lcom/facebook/hermes/instrumentation/HermesMemoryDumper;", "", "shouldSaveSnapshot", "", "getInternalStorage", "", "getId", "setMetaData", "", "crashId", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface HermesMemoryDumper {
    String getId();

    String getInternalStorage();

    void setMetaData(String crashId);

    boolean shouldSaveSnapshot();
}
