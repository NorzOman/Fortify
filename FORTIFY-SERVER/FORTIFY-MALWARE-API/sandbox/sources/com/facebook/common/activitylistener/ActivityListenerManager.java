package com.facebook.common.activitylistener;

import android.app.Activity;
import android.content.Context;
import android.content.ContextWrapper;
import com.facebook.common.internal.Preconditions;
import java.lang.ref.WeakReference;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public class ActivityListenerManager {
    public static void register(ActivityListener activityListener, Context context) {
        ListenableActivity listenableActivity = getListenableActivity(context);
        if (listenableActivity != null) {
            listenableActivity.addActivityListener(new Listener(activityListener));
        }
    }

    @Nullable
    public static ListenableActivity getListenableActivity(Context context) {
        boolean z = context instanceof ListenableActivity;
        Object baseContext = context;
        if (!z) {
            boolean z2 = context instanceof ContextWrapper;
            baseContext = context;
            if (z2) {
                baseContext = ((ContextWrapper) context).getBaseContext();
            }
        }
        if (baseContext instanceof ListenableActivity) {
            return (ListenableActivity) baseContext;
        }
        return null;
    }

    private static class Listener extends BaseActivityListener {
        private final WeakReference<ActivityListener> mActivityListenerRef;

        public Listener(ActivityListener activityListener) {
            this.mActivityListenerRef = new WeakReference<>(activityListener);
        }

        @Override // com.facebook.common.activitylistener.BaseActivityListener, com.facebook.common.activitylistener.ActivityListener
        public void onActivityCreate(Activity activity) {
            ActivityListener listenerOrCleanUp = getListenerOrCleanUp(activity);
            if (listenerOrCleanUp != null) {
                listenerOrCleanUp.onActivityCreate(activity);
            }
        }

        @Override // com.facebook.common.activitylistener.BaseActivityListener, com.facebook.common.activitylistener.ActivityListener
        public void onDestroy(Activity activity) {
            ActivityListener listenerOrCleanUp = getListenerOrCleanUp(activity);
            if (listenerOrCleanUp != null) {
                listenerOrCleanUp.onDestroy(activity);
            }
        }

        @Override // com.facebook.common.activitylistener.BaseActivityListener, com.facebook.common.activitylistener.ActivityListener
        public void onStart(Activity activity) {
            ActivityListener listenerOrCleanUp = getListenerOrCleanUp(activity);
            if (listenerOrCleanUp != null) {
                listenerOrCleanUp.onStart(activity);
            }
        }

        @Override // com.facebook.common.activitylistener.BaseActivityListener, com.facebook.common.activitylistener.ActivityListener
        public void onStop(Activity activity) {
            ActivityListener listenerOrCleanUp = getListenerOrCleanUp(activity);
            if (listenerOrCleanUp != null) {
                listenerOrCleanUp.onStop(activity);
            }
        }

        @Override // com.facebook.common.activitylistener.BaseActivityListener, com.facebook.common.activitylistener.ActivityListener
        public void onResume(Activity activity) {
            ActivityListener listenerOrCleanUp = getListenerOrCleanUp(activity);
            if (listenerOrCleanUp != null) {
                listenerOrCleanUp.onResume(activity);
            }
        }

        @Override // com.facebook.common.activitylistener.BaseActivityListener, com.facebook.common.activitylistener.ActivityListener
        public void onPause(Activity activity) {
            ActivityListener listenerOrCleanUp = getListenerOrCleanUp(activity);
            if (listenerOrCleanUp != null) {
                listenerOrCleanUp.onPause(activity);
            }
        }

        /* JADX WARN: Multi-variable type inference failed */
        @Nullable
        private ActivityListener getListenerOrCleanUp(Activity activity) {
            ActivityListener activityListener = this.mActivityListenerRef.get();
            if (activityListener == null) {
                Preconditions.checkArgument(Boolean.valueOf(activity instanceof ListenableActivity));
                ((ListenableActivity) activity).removeActivityListener(this);
            }
            return activityListener;
        }
    }
}
