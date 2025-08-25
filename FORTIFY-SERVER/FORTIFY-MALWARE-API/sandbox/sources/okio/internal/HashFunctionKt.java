package okio.internal;

import java.security.MessageDigest;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: HashFunction.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000\u000e\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\u001a\u0010\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u0003H\u0000¨\u0006\u0004"}, d2 = {"newHashFunction", "Lokio/internal/HashFunction;", "algorithm", "", "okio"}, k = 2, mv = {1, 4, 0})
/* loaded from: classes2.dex */
public final class HashFunctionKt {
    public static final HashFunction newHashFunction(String algorithm) {
        Intrinsics.checkNotNullParameter(algorithm, "algorithm");
        return new HashFunction(algorithm) { // from class: okio.internal.HashFunctionKt.newHashFunction.1
            final /* synthetic */ String $algorithm;
            private final MessageDigest digest;

            {
                this.$algorithm = algorithm;
                this.digest = MessageDigest.getInstance(algorithm);
            }

            @Override // okio.internal.HashFunction
            public void update(byte[] input, int offset, int byteCount) {
                Intrinsics.checkNotNullParameter(input, "input");
                this.digest.update(input, offset, byteCount);
            }

            @Override // okio.internal.HashFunction
            public byte[] digest() {
                return this.digest.digest();
            }
        };
    }
}
