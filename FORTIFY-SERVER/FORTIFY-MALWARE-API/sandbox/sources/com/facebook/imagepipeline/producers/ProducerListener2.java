package com.facebook.imagepipeline.producers;

import java.util.Map;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public interface ProducerListener2 {
    void onProducerEvent(ProducerContext producerContext, String str, String str2);

    void onProducerFinishWithCancellation(ProducerContext producerContext, String str, @Nullable Map<String, String> map);

    void onProducerFinishWithFailure(ProducerContext producerContext, String str, Throwable th, @Nullable Map<String, String> map);

    void onProducerFinishWithSuccess(ProducerContext producerContext, String str, @Nullable Map<String, String> map);

    void onProducerStart(ProducerContext producerContext, String str);

    void onUltimateProducerReached(ProducerContext producerContext, String str, boolean z);

    boolean requiresExtraMap(ProducerContext producerContext, String str);
}
