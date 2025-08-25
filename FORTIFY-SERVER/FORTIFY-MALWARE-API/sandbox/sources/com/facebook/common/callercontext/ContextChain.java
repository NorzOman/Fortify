package com.facebook.common.callercontext;

import android.os.Parcel;
import android.os.Parcelable;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public class ContextChain implements Parcelable {
    public static final Parcelable.Creator<ContextChain> CREATOR = new Parcelable.Creator<ContextChain>() { // from class: com.facebook.common.callercontext.ContextChain.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public ContextChain createFromParcel(Parcel parcel) {
            return new ContextChain(parcel);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public ContextChain[] newArray(int i) {
            return new ContextChain[i];
        }
    };
    private static final char PARENT_SEPARATOR = '/';
    public static final String TAG_INFRA = "i";
    public static final String TAG_PRODUCT = "p";
    public static final String TAG_PRODUCT_AND_INFRA = "pi";
    private static boolean sUseConcurrentHashMap = false;

    @Nullable
    private Map<String, Object> mExtraData;
    private final String mName;

    @Nullable
    private final ContextChain mParent;

    @Nullable
    private String mSerializedChainString;
    private String mSerializedNodeString;
    private final String mTag;

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public ContextChain(String str, String str2, @Nullable Map<String, String> map, @Nullable ContextChain contextChain) {
        this.mTag = str;
        this.mName = str2;
        this.mSerializedNodeString = str + ":" + str2;
        this.mParent = contextChain;
        initializeExtraData(contextChain, map);
    }

    private void initializeExtraData(@Nullable ContextChain contextChain, @Nullable Map<String, ?> map) {
        Map<String, Object> extraData = contextChain != null ? contextChain.getExtraData() : null;
        if (extraData != null) {
            if (sUseConcurrentHashMap) {
                this.mExtraData = new ConcurrentHashMap(extraData);
            } else {
                this.mExtraData = new HashMap(extraData);
            }
        }
        if (map != null) {
            if (this.mExtraData == null) {
                if (sUseConcurrentHashMap) {
                    this.mExtraData = new ConcurrentHashMap();
                } else {
                    this.mExtraData = new HashMap();
                }
            }
            this.mExtraData.putAll(map);
        }
    }

    public ContextChain(String str, @Nullable Map<String, Object> map, @Nullable ContextChain contextChain) {
        this.mTag = "serialized_tag";
        this.mName = "serialized_name";
        this.mSerializedNodeString = str;
        this.mParent = contextChain;
        initializeExtraData(contextChain, map);
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public ContextChain(String str, @Nullable ContextChain contextChain) {
        this(str, (Map<String, Object>) null, contextChain);
    }

    public ContextChain(String str, String str2, @Nullable ContextChain contextChain) {
        this(str, str2, null, contextChain);
    }

    protected ContextChain(Parcel parcel) {
        this.mTag = parcel.readString();
        this.mName = parcel.readString();
        this.mSerializedNodeString = parcel.readString();
        this.mParent = (ContextChain) parcel.readParcelable(ContextChain.class.getClassLoader());
    }

    public static void setUseConcurrentHashMap(boolean z) {
        sUseConcurrentHashMap = z;
    }

    public String getName() {
        return this.mName;
    }

    public String getTag() {
        return this.mTag;
    }

    @Nullable
    public Map<String, Object> getExtraData() {
        return this.mExtraData;
    }

    @Nullable
    public ContextChain getParent() {
        return this.mParent;
    }

    public ContextChain getRootContextChain() {
        ContextChain contextChain = this.mParent;
        return contextChain == null ? this : contextChain.getRootContextChain();
    }

    @Nullable
    public String getStringExtra(String str) {
        Object obj;
        Map<String, Object> map = this.mExtraData;
        if (map == null) {
            return null;
        }
        if ((sUseConcurrentHashMap && str == null) || (obj = map.get(str)) == null) {
            return null;
        }
        return String.valueOf(obj);
    }

    public void putObjectExtra(String str, Object obj) {
        boolean z = sUseConcurrentHashMap;
        if (z && (str == null || obj == null)) {
            return;
        }
        if (this.mExtraData == null) {
            if (z) {
                this.mExtraData = new ConcurrentHashMap();
            } else {
                this.mExtraData = new HashMap();
            }
        }
        this.mExtraData.put(str, obj);
    }

    public String toString() {
        if (this.mSerializedChainString == null) {
            this.mSerializedChainString = getNodeString();
            if (this.mParent != null) {
                this.mSerializedChainString = this.mParent.toString() + PARENT_SEPARATOR + this.mSerializedChainString;
            }
        }
        return this.mSerializedChainString;
    }

    protected String getNodeString() {
        return this.mSerializedNodeString;
    }

    public String[] toStringArray() {
        return toString().split(String.valueOf(PARENT_SEPARATOR));
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        ContextChain contextChain = (ContextChain) obj;
        return Objects.equals(getNodeString(), contextChain.getNodeString()) && Objects.equals(this.mParent, contextChain.mParent);
    }

    public int hashCode() {
        return Objects.hash(this.mParent, getNodeString());
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i) {
        parcel.writeString(this.mTag);
        parcel.writeString(this.mName);
        parcel.writeString(getNodeString());
        parcel.writeParcelable(this.mParent, i);
    }
}
