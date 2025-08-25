package com.facebook.imagepipeline.producers;

import com.facebook.imagepipeline.producers.FetchState;
import java.util.Map;
import kotlin.Metadata;

/* compiled from: BaseNetworkFetcher.kt */
@Metadata(d1 = {"\u00004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010$\n\u0002\u0010\u000e\n\u0002\b\u0002\b&\u0018\u0000*\n\b\u0000\u0010\u0001*\u0004\u0018\u00010\u00022\b\u0012\u0004\u0012\u0002H\u00010\u0003B\u0007¢\u0006\u0004\b\u0004\u0010\u0005J\u0015\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00028\u0000H\u0016¢\u0006\u0002\u0010\tJ\u001d\u0010\n\u001a\u00020\u000b2\u0006\u0010\b\u001a\u00028\u00002\u0006\u0010\f\u001a\u00020\rH\u0016¢\u0006\u0002\u0010\u000eJ+\u0010\u000f\u001a\u0010\u0012\u0004\u0012\u00020\u0011\u0012\u0004\u0012\u00020\u0011\u0018\u00010\u00102\u0006\u0010\b\u001a\u00028\u00002\u0006\u0010\f\u001a\u00020\rH\u0016¢\u0006\u0002\u0010\u0012¨\u0006\u0013"}, d2 = {"Lcom/facebook/imagepipeline/producers/BaseNetworkFetcher;", "FETCH_STATE", "Lcom/facebook/imagepipeline/producers/FetchState;", "Lcom/facebook/imagepipeline/producers/NetworkFetcher;", "<init>", "()V", "shouldPropagate", "", "fetchState", "(Lcom/facebook/imagepipeline/producers/FetchState;)Z", "onFetchCompletion", "", "byteSize", "", "(Lcom/facebook/imagepipeline/producers/FetchState;I)V", "getExtraMap", "", "", "(Lcom/facebook/imagepipeline/producers/FetchState;I)Ljava/util/Map;", "imagepipeline_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public abstract class BaseNetworkFetcher<FETCH_STATE extends FetchState> implements NetworkFetcher<FETCH_STATE> {
    @Override // com.facebook.imagepipeline.producers.NetworkFetcher
    public Map<String, String> getExtraMap(FETCH_STATE fetchState, int byteSize) {
        return null;
    }

    @Override // com.facebook.imagepipeline.producers.NetworkFetcher
    public void onFetchCompletion(FETCH_STATE fetchState, int byteSize) {
    }

    @Override // com.facebook.imagepipeline.producers.NetworkFetcher
    public boolean shouldPropagate(FETCH_STATE fetchState) {
        return true;
    }
}
