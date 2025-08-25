package com.facebook.react.bridge;

import android.os.SystemClock;
import java.util.Iterator;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CopyOnWriteArrayList;

/* loaded from: classes.dex */
public class ReactMarker {
    private static Queue<ReactMarkerRecord> sNativeReactMarkerQueue = new ConcurrentLinkedQueue();
    private static final List<MarkerListener> sListeners = new CopyOnWriteArrayList();
    private static final List<FabricMarkerListener> sFabricMarkerListeners = new CopyOnWriteArrayList();

    public interface MarkerListener {
        void logMarker(ReactMarkerConstants reactMarkerConstants, String str, int i);
    }

    private static native void nativeLogMarker(String str, long j);

    private static class ReactMarkerRecord {
        private final String mMarkerName;
        private final long mMarkerTime;

        public ReactMarkerRecord(String str, long j) {
            this.mMarkerName = str;
            this.mMarkerTime = j;
        }

        public String getMarkerName() {
            return this.mMarkerName;
        }

        public long getMarkerTime() {
            return this.mMarkerTime;
        }
    }

    public interface FabricMarkerListener {
        void logFabricMarker(ReactMarkerConstants reactMarkerConstants, String str, int i, long j);

        default void logFabricMarker(ReactMarkerConstants reactMarkerConstants, String str, int i, long j, int i2) {
            logFabricMarker(reactMarkerConstants, str, i, j);
        }
    }

    public static void addListener(MarkerListener markerListener) {
        List<MarkerListener> list = sListeners;
        if (list.contains(markerListener)) {
            return;
        }
        list.add(markerListener);
    }

    public static void removeListener(MarkerListener markerListener) {
        sListeners.remove(markerListener);
    }

    public static void clearMarkerListeners() {
        sListeners.clear();
    }

    public static void addFabricListener(FabricMarkerListener fabricMarkerListener) {
        List<FabricMarkerListener> list = sFabricMarkerListeners;
        if (list.contains(fabricMarkerListener)) {
            return;
        }
        list.add(fabricMarkerListener);
    }

    public static void removeFabricListener(FabricMarkerListener fabricMarkerListener) {
        sFabricMarkerListeners.remove(fabricMarkerListener);
    }

    public static void clearFabricMarkerListeners() {
        sFabricMarkerListeners.clear();
    }

    public static void logFabricMarker(ReactMarkerConstants reactMarkerConstants, String str, int i, long j, int i2) {
        Iterator<FabricMarkerListener> it = sFabricMarkerListeners.iterator();
        while (it.hasNext()) {
            it.next().logFabricMarker(reactMarkerConstants, str, i, j, i2);
        }
    }

    public static void logFabricMarker(ReactMarkerConstants reactMarkerConstants, String str, int i, long j) {
        Iterator<FabricMarkerListener> it = sFabricMarkerListeners.iterator();
        while (it.hasNext()) {
            it.next().logFabricMarker(reactMarkerConstants, str, i, j, 0);
        }
    }

    public static void logFabricMarker(ReactMarkerConstants reactMarkerConstants, String str, int i) {
        logFabricMarker(reactMarkerConstants, str, i, SystemClock.uptimeMillis(), 0);
    }

    public static void logMarker(String str) {
        logMarker(str, (String) null);
    }

    public static void logMarker(String str, int i) {
        logMarker(str, (String) null, i);
    }

    public static void logMarker(String str, String str2) {
        logMarker(str, str2, 0);
    }

    public static void logMarker(String str, String str2, int i) {
        logMarker(ReactMarkerConstants.valueOf(str), str2, i);
    }

    public static void logMarker(ReactMarkerConstants reactMarkerConstants) {
        logMarker(reactMarkerConstants, (String) null, 0);
    }

    public static void logMarker(ReactMarkerConstants reactMarkerConstants, int i) {
        logMarker(reactMarkerConstants, (String) null, i);
    }

    public static void logMarker(ReactMarkerConstants reactMarkerConstants, String str) {
        logMarker(reactMarkerConstants, str, 0);
    }

    public static void logMarker(ReactMarkerConstants reactMarkerConstants, long j) {
        logMarker(reactMarkerConstants, null, 0, Long.valueOf(j));
    }

    public static void logMarker(ReactMarkerConstants reactMarkerConstants, String str, int i) {
        logMarker(reactMarkerConstants, str, i, null);
    }

    public static void logMarker(ReactMarkerConstants reactMarkerConstants, String str, int i, Long l) {
        logFabricMarker(reactMarkerConstants, str, i);
        Iterator<MarkerListener> it = sListeners.iterator();
        while (it.hasNext()) {
            it.next().logMarker(reactMarkerConstants, str, i);
        }
        notifyNativeMarker(reactMarkerConstants, l);
    }

    private static void notifyNativeMarker(ReactMarkerConstants reactMarkerConstants, Long l) {
        if (!reactMarkerConstants.hasMatchingNameMarker()) {
            return;
        }
        if (l == null) {
            l = Long.valueOf(SystemClock.uptimeMillis());
        }
        if (ReactBridge.isInitialized()) {
            nativeLogMarker(reactMarkerConstants.name(), l.longValue());
            while (true) {
                ReactMarkerRecord reactMarkerRecordPoll = sNativeReactMarkerQueue.poll();
                if (reactMarkerRecordPoll == null) {
                    return;
                } else {
                    nativeLogMarker(reactMarkerRecordPoll.getMarkerName(), reactMarkerRecordPoll.getMarkerTime());
                }
            }
        } else {
            sNativeReactMarkerQueue.add(new ReactMarkerRecord(reactMarkerConstants.name(), l.longValue()));
        }
    }
}
