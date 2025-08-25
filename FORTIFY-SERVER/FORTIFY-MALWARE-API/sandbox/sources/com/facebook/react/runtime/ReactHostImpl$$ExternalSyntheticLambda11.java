package com.facebook.react.runtime;

import com.facebook.react.runtime.internal.bolts.Continuation;
import com.facebook.react.runtime.internal.bolts.Task;

/* compiled from: D8$$SyntheticClass */
/* loaded from: classes.dex */
public final /* synthetic */ class ReactHostImpl$$ExternalSyntheticLambda11 implements Continuation {
    @Override // com.facebook.react.runtime.internal.bolts.Continuation
    public final Object then(Task task) {
        return (Task) task.getResult();
    }
}
