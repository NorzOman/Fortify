package com.facebook.react.uimanager;

import android.util.SparseArray;
import android.util.SparseBooleanArray;
import com.facebook.react.common.SingleThreadAsserter;

/* loaded from: classes.dex */
class ShadowNodeRegistry {
    private final SparseArray<ReactShadowNode> mTagsToCSSNodes = new SparseArray<>();
    private final SparseBooleanArray mRootTags = new SparseBooleanArray();
    private final SingleThreadAsserter mThreadAsserter = new SingleThreadAsserter();

    public void addRootNode(ReactShadowNode reactShadowNode) {
        this.mThreadAsserter.assertNow();
        int reactTag = reactShadowNode.getReactTag();
        this.mTagsToCSSNodes.put(reactTag, reactShadowNode);
        this.mRootTags.put(reactTag, true);
    }

    public void removeRootNode(int i) {
        this.mThreadAsserter.assertNow();
        if (i == -1) {
            return;
        }
        if (!this.mRootTags.get(i)) {
            throw new IllegalViewOperationException("View with tag " + i + " is not registered as a root view");
        }
        this.mTagsToCSSNodes.remove(i);
        this.mRootTags.delete(i);
    }

    public void addNode(ReactShadowNode reactShadowNode) {
        this.mThreadAsserter.assertNow();
        this.mTagsToCSSNodes.put(reactShadowNode.getReactTag(), reactShadowNode);
    }

    public void removeNode(int i) {
        this.mThreadAsserter.assertNow();
        if (this.mRootTags.get(i)) {
            throw new IllegalViewOperationException("Trying to remove root node " + i + " without using removeRootNode!");
        }
        this.mTagsToCSSNodes.remove(i);
    }

    public ReactShadowNode getNode(int i) {
        this.mThreadAsserter.assertNow();
        return this.mTagsToCSSNodes.get(i);
    }

    public boolean isRootNode(int i) {
        this.mThreadAsserter.assertNow();
        return this.mRootTags.get(i);
    }

    public int getRootNodeCount() {
        this.mThreadAsserter.assertNow();
        return this.mRootTags.size();
    }

    public int getRootTag(int i) {
        this.mThreadAsserter.assertNow();
        return this.mRootTags.keyAt(i);
    }
}
