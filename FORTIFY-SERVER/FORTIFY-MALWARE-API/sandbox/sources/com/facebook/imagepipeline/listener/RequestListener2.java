package com.facebook.imagepipeline.listener;

import com.facebook.imagepipeline.producers.ProducerContext;
import com.facebook.imagepipeline.producers.ProducerListener2;

/* loaded from: classes.dex */
public interface RequestListener2 extends ProducerListener2 {
    void onRequestCancellation(ProducerContext producerContext);

    void onRequestFailure(ProducerContext producerContext, Throwable th);

    void onRequestStart(ProducerContext producerContext);

    void onRequestSuccess(ProducerContext producerContext);
}
