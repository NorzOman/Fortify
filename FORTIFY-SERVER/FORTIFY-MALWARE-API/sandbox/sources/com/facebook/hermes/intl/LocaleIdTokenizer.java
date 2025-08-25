package com.facebook.hermes.intl;

/* compiled from: LocaleIdentifier.java */
/* loaded from: classes.dex */
class LocaleIdTokenizer {
    private CharSequence mLocaleIdBuffer;
    int mCurrentSubtagStart = 0;
    int mCurrentSubtagEnd = -1;

    private static boolean isSubtagSeparator(char c) {
        return c == '-';
    }

    /* compiled from: LocaleIdentifier.java */
    public class LocaleIdSubtagIterationFailed extends Exception {
        public LocaleIdSubtagIterationFailed() {
        }
    }

    /* compiled from: LocaleIdentifier.java */
    public class LocaleIdSubtag {
        private CharSequence mLocaleIdBuffer;
        private int mSubtagEnd;
        private int mSubtagStart;

        LocaleIdSubtag(CharSequence charSequence, int i, int i2) {
            this.mLocaleIdBuffer = charSequence;
            this.mSubtagStart = i;
            this.mSubtagEnd = i2;
        }

        public void reset() {
            this.mLocaleIdBuffer = "";
            this.mSubtagStart = 0;
            this.mSubtagEnd = 0;
        }

        public String toString() {
            return this.mLocaleIdBuffer.subSequence(this.mSubtagStart, this.mSubtagEnd + 1).toString();
        }

        public String toLowerString() {
            StringBuffer stringBuffer = new StringBuffer();
            for (int i = this.mSubtagStart; i <= this.mSubtagEnd; i++) {
                stringBuffer.append(Character.toLowerCase(this.mLocaleIdBuffer.charAt(i)));
            }
            return stringBuffer.toString();
        }

        public String toUpperString() {
            StringBuffer stringBuffer = new StringBuffer();
            for (int i = this.mSubtagStart; i <= this.mSubtagEnd; i++) {
                stringBuffer.append(Character.toUpperCase(this.mLocaleIdBuffer.charAt(i)));
            }
            return stringBuffer.toString();
        }

        public String toTitleString() {
            StringBuffer stringBuffer = new StringBuffer();
            for (int i = this.mSubtagStart; i <= this.mSubtagEnd; i++) {
                if (i == this.mSubtagStart) {
                    stringBuffer.append(Character.toUpperCase(this.mLocaleIdBuffer.charAt(i)));
                } else {
                    stringBuffer.append(Character.toLowerCase(this.mLocaleIdBuffer.charAt(i)));
                }
            }
            return stringBuffer.toString();
        }

        public boolean isUnicodeLanguageSubtag() {
            return IntlTextUtils.isUnicodeLanguageSubtag(this.mLocaleIdBuffer, this.mSubtagStart, this.mSubtagEnd);
        }

        public boolean isExtensionSingleton() {
            return IntlTextUtils.isExtensionSingleton(this.mLocaleIdBuffer, this.mSubtagStart, this.mSubtagEnd);
        }

        public boolean isUnicodeScriptSubtag() {
            return IntlTextUtils.isUnicodeScriptSubtag(this.mLocaleIdBuffer, this.mSubtagStart, this.mSubtagEnd);
        }

        public boolean isUnicodeRegionSubtag() {
            return IntlTextUtils.isUnicodeRegionSubtag(this.mLocaleIdBuffer, this.mSubtagStart, this.mSubtagEnd);
        }

        public boolean isUnicodeVariantSubtag() {
            return IntlTextUtils.isUnicodeVariantSubtag(this.mLocaleIdBuffer, this.mSubtagStart, this.mSubtagEnd);
        }

        public boolean isUnicodeExtensionAttribute() {
            return IntlTextUtils.isUnicodeExtensionAttribute(this.mLocaleIdBuffer, this.mSubtagStart, this.mSubtagEnd);
        }

        public boolean isUnicodeExtensionKey() {
            return IntlTextUtils.isUnicodeExtensionKey(this.mLocaleIdBuffer, this.mSubtagStart, this.mSubtagEnd);
        }

        public boolean isUnicodeExtensionKeyTypeItem() {
            return IntlTextUtils.isUnicodeExtensionKeyTypeItem(this.mLocaleIdBuffer, this.mSubtagStart, this.mSubtagEnd);
        }

        public boolean isTranformedExtensionTKey() {
            return IntlTextUtils.isTranformedExtensionTKey(this.mLocaleIdBuffer, this.mSubtagStart, this.mSubtagEnd);
        }

        public boolean isTranformedExtensionTValueItem() {
            return IntlTextUtils.isTranformedExtensionTValueItem(this.mLocaleIdBuffer, this.mSubtagStart, this.mSubtagEnd);
        }

        public boolean isPrivateUseExtension() {
            return IntlTextUtils.isPrivateUseExtension(this.mLocaleIdBuffer, this.mSubtagStart, this.mSubtagEnd);
        }

        public boolean isOtherExtension() {
            return IntlTextUtils.isOtherExtension(this.mLocaleIdBuffer, this.mSubtagStart, this.mSubtagEnd);
        }
    }

    public LocaleIdTokenizer(CharSequence charSequence) {
        this.mLocaleIdBuffer = charSequence;
    }

    public boolean hasMoreSubtags() {
        return this.mLocaleIdBuffer.length() > 0 && this.mCurrentSubtagEnd < this.mLocaleIdBuffer.length() - 1;
    }

    public LocaleIdSubtag nextSubtag() throws LocaleIdSubtagIterationFailed {
        if (!hasMoreSubtags()) {
            throw new LocaleIdSubtagIterationFailed();
        }
        int i = this.mCurrentSubtagEnd;
        if (i >= this.mCurrentSubtagStart) {
            if (!isSubtagSeparator(this.mLocaleIdBuffer.charAt(i + 1))) {
                throw new LocaleIdSubtagIterationFailed();
            }
            if (this.mCurrentSubtagEnd + 2 == this.mLocaleIdBuffer.length()) {
                throw new LocaleIdSubtagIterationFailed();
            }
            this.mCurrentSubtagStart = this.mCurrentSubtagEnd + 2;
        }
        this.mCurrentSubtagEnd = this.mCurrentSubtagStart;
        while (this.mCurrentSubtagEnd < this.mLocaleIdBuffer.length() && !isSubtagSeparator(this.mLocaleIdBuffer.charAt(this.mCurrentSubtagEnd))) {
            this.mCurrentSubtagEnd++;
        }
        int i2 = this.mCurrentSubtagEnd;
        if (i2 > this.mCurrentSubtagStart) {
            this.mCurrentSubtagEnd = i2 - 1;
            return new LocaleIdSubtag(this.mLocaleIdBuffer, this.mCurrentSubtagStart, this.mCurrentSubtagEnd);
        }
        throw new LocaleIdSubtagIterationFailed();
    }
}
