package com.facebook.react.fabric;

import com.facebook.react.bridge.ReactMarker;
import com.facebook.react.bridge.ReactMarkerConstants;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/* loaded from: classes.dex */
public class DevToolsReactPerfLogger implements ReactMarker.FabricMarkerListener {
    static final LongStreamingStats mStreamingCommitStats = new LongStreamingStats();
    static final LongStreamingStats mStreamingLayoutStats = new LongStreamingStats();
    static final LongStreamingStats mStreamingDiffStats = new LongStreamingStats();
    static final LongStreamingStats mStreamingTransactionEndStats = new LongStreamingStats();
    static final LongStreamingStats mStreamingBatchExecutionStats = new LongStreamingStats();
    private final Map<Integer, FabricCommitPoint> mFabricCommitMarkers = new HashMap();
    private final List<DevToolsReactPerfLoggerListener> mDevToolsReactPerfLoggerListeners = new ArrayList();

    public interface DevToolsReactPerfLoggerListener {
        void onFabricCommitEnd(FabricCommitPoint fabricCommitPoint);
    }

    private static class FabricCommitPointData {
        private final int mCounter;
        private final long mTimeStamp;

        public FabricCommitPointData(long j, int i) {
            this.mTimeStamp = j;
            this.mCounter = i;
        }

        public long getTimeStamp() {
            return this.mTimeStamp;
        }

        public int getCounter() {
            return this.mCounter;
        }
    }

    public static class FabricCommitPoint {
        private final long mCommitNumber;
        private final Map<ReactMarkerConstants, FabricCommitPointData> mPoints;

        private FabricCommitPoint(int i) {
            this.mPoints = new HashMap();
            this.mCommitNumber = i;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addPoint(ReactMarkerConstants reactMarkerConstants, FabricCommitPointData fabricCommitPointData) {
            this.mPoints.put(reactMarkerConstants, fabricCommitPointData);
        }

        private long getTimestamp(ReactMarkerConstants reactMarkerConstants) {
            FabricCommitPointData fabricCommitPointData = this.mPoints.get(reactMarkerConstants);
            if (fabricCommitPointData != null) {
                return fabricCommitPointData.getTimeStamp();
            }
            return -1L;
        }

        private int getCounter(ReactMarkerConstants reactMarkerConstants) {
            FabricCommitPointData fabricCommitPointData = this.mPoints.get(reactMarkerConstants);
            if (fabricCommitPointData != null) {
                return fabricCommitPointData.getCounter();
            }
            return 0;
        }

        public long getCommitNumber() {
            return this.mCommitNumber;
        }

        public long getCommitStart() {
            return getTimestamp(ReactMarkerConstants.FABRIC_COMMIT_START);
        }

        public long getCommitEnd() {
            return getTimestamp(ReactMarkerConstants.FABRIC_COMMIT_END);
        }

        public long getFinishTransactionStart() {
            return getTimestamp(ReactMarkerConstants.FABRIC_FINISH_TRANSACTION_START);
        }

        public long getFinishTransactionEnd() {
            return getTimestamp(ReactMarkerConstants.FABRIC_FINISH_TRANSACTION_END);
        }

        public long getDiffStart() {
            return getTimestamp(ReactMarkerConstants.FABRIC_DIFF_START);
        }

        public long getDiffEnd() {
            return getTimestamp(ReactMarkerConstants.FABRIC_DIFF_END);
        }

        public long getLayoutStart() {
            return getTimestamp(ReactMarkerConstants.FABRIC_LAYOUT_START);
        }

        public long getLayoutEnd() {
            return getTimestamp(ReactMarkerConstants.FABRIC_LAYOUT_END);
        }

        public int getAffectedLayoutNodesCount() {
            return getCounter(ReactMarkerConstants.FABRIC_LAYOUT_AFFECTED_NODES);
        }

        public long getAffectedLayoutNodesCountTime() {
            return getTimestamp(ReactMarkerConstants.FABRIC_LAYOUT_AFFECTED_NODES);
        }

        public long getBatchExecutionStart() {
            return getTimestamp(ReactMarkerConstants.FABRIC_BATCH_EXECUTION_START);
        }

        public long getBatchExecutionEnd() {
            return getTimestamp(ReactMarkerConstants.FABRIC_BATCH_EXECUTION_END);
        }

        public long getUpdateUIMainThreadStart() {
            return getTimestamp(ReactMarkerConstants.FABRIC_UPDATE_UI_MAIN_THREAD_START);
        }

        public long getUpdateUIMainThreadEnd() {
            return getTimestamp(ReactMarkerConstants.FABRIC_UPDATE_UI_MAIN_THREAD_END);
        }

        public long getCommitDuration() {
            return getCommitEnd() - getCommitStart();
        }

        public long getLayoutDuration() {
            return getLayoutEnd() - getLayoutStart();
        }

        public long getDiffDuration() {
            return getDiffEnd() - getDiffStart();
        }

        public long getTransactionEndDuration() {
            return getFinishTransactionEnd() - getFinishTransactionStart();
        }

        public long getBatchExecutionDuration() {
            return getBatchExecutionEnd() - getBatchExecutionStart();
        }

        public String toString() {
            StringBuilder sb = new StringBuilder("FabricCommitPoint{mCommitNumber=");
            sb.append(this.mCommitNumber);
            sb.append(", mPoints=").append(this.mPoints);
            sb.append('}');
            return sb.toString();
        }
    }

    public void addDevToolsReactPerfLoggerListener(DevToolsReactPerfLoggerListener devToolsReactPerfLoggerListener) {
        this.mDevToolsReactPerfLoggerListeners.add(devToolsReactPerfLoggerListener);
    }

    public void removeDevToolsReactPerfLoggerListener(DevToolsReactPerfLoggerListener devToolsReactPerfLoggerListener) {
        this.mDevToolsReactPerfLoggerListeners.remove(devToolsReactPerfLoggerListener);
    }

    @Override // com.facebook.react.bridge.ReactMarker.FabricMarkerListener
    public void logFabricMarker(ReactMarkerConstants reactMarkerConstants, String str, int i, long j) {
        logFabricMarker(reactMarkerConstants, str, i, j, 0);
    }

    @Override // com.facebook.react.bridge.ReactMarker.FabricMarkerListener
    public void logFabricMarker(ReactMarkerConstants reactMarkerConstants, String str, int i, long j, int i2) {
        if (isFabricCommitMarker(reactMarkerConstants)) {
            FabricCommitPoint fabricCommitPoint = this.mFabricCommitMarkers.get(Integer.valueOf(i));
            if (fabricCommitPoint == null) {
                fabricCommitPoint = new FabricCommitPoint(i);
                this.mFabricCommitMarkers.put(Integer.valueOf(i), fabricCommitPoint);
            }
            fabricCommitPoint.addPoint(reactMarkerConstants, new FabricCommitPointData(j, i2));
            if (reactMarkerConstants != ReactMarkerConstants.FABRIC_BATCH_EXECUTION_END || j <= 0) {
                return;
            }
            onFabricCommitEnd(fabricCommitPoint);
            this.mFabricCommitMarkers.remove(Integer.valueOf(i));
        }
    }

    private void onFabricCommitEnd(FabricCommitPoint fabricCommitPoint) {
        Iterator<DevToolsReactPerfLoggerListener> it = this.mDevToolsReactPerfLoggerListeners.iterator();
        while (it.hasNext()) {
            it.next().onFabricCommitEnd(fabricCommitPoint);
        }
    }

    private static boolean isFabricCommitMarker(ReactMarkerConstants reactMarkerConstants) {
        return reactMarkerConstants == ReactMarkerConstants.FABRIC_COMMIT_START || reactMarkerConstants == ReactMarkerConstants.FABRIC_COMMIT_END || reactMarkerConstants == ReactMarkerConstants.FABRIC_FINISH_TRANSACTION_START || reactMarkerConstants == ReactMarkerConstants.FABRIC_FINISH_TRANSACTION_END || reactMarkerConstants == ReactMarkerConstants.FABRIC_DIFF_START || reactMarkerConstants == ReactMarkerConstants.FABRIC_DIFF_END || reactMarkerConstants == ReactMarkerConstants.FABRIC_LAYOUT_START || reactMarkerConstants == ReactMarkerConstants.FABRIC_LAYOUT_END || reactMarkerConstants == ReactMarkerConstants.FABRIC_BATCH_EXECUTION_START || reactMarkerConstants == ReactMarkerConstants.FABRIC_BATCH_EXECUTION_END || reactMarkerConstants == ReactMarkerConstants.FABRIC_UPDATE_UI_MAIN_THREAD_START || reactMarkerConstants == ReactMarkerConstants.FABRIC_UPDATE_UI_MAIN_THREAD_END || reactMarkerConstants == ReactMarkerConstants.FABRIC_LAYOUT_AFFECTED_NODES;
    }
}
