package com.facebook.hermes.intl;

/* loaded from: classes.dex */
public class IntlTextUtils {
    static final /* synthetic */ boolean $assertionsDisabled = false;

    public static boolean isASCIIDigit(char c) {
        return c >= '0' && c <= '9';
    }

    public static boolean isASCIILetter(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    }

    public static boolean isASCIILetterOrDigit(char c) {
        return isASCIILetter(c) || isASCIIDigit(c);
    }

    public static boolean isAlphaNum(CharSequence charSequence, int i, int i2, int i3, int i4) {
        int i5;
        if (i2 >= charSequence.length() || (i5 = (i2 - i) + 1) < i3 || i5 > i4) {
            return false;
        }
        while (i <= i2) {
            if (!isASCIILetterOrDigit(charSequence.charAt(i))) {
                return false;
            }
            i++;
        }
        return true;
    }

    public static boolean isAlpha(CharSequence charSequence, int i, int i2, int i3, int i4) {
        int i5;
        if (i2 >= charSequence.length() || (i5 = (i2 - i) + 1) < i3 || i5 > i4) {
            return false;
        }
        while (i <= i2) {
            if (!isASCIILetter(charSequence.charAt(i))) {
                return false;
            }
            i++;
        }
        return true;
    }

    public static boolean isDigit(CharSequence charSequence, int i, int i2, int i3, int i4) {
        int i5;
        if (i2 >= charSequence.length() || (i5 = (i2 - i) + 1) < i3 || i5 > i4) {
            return false;
        }
        while (i <= i2) {
            if (!isASCIIDigit(charSequence.charAt(i))) {
                return false;
            }
            i++;
        }
        return true;
    }

    public static boolean isDigitAlphanum3(CharSequence charSequence, int i, int i2) {
        return (i2 - i) + 1 == 4 && isASCIILetter(charSequence.charAt(i)) && isAlphaNum(charSequence, i + 1, i2, 3, 3);
    }

    public static boolean isUnicodeLanguageSubtag(CharSequence charSequence, int i, int i2) {
        if (isAlpha(charSequence, i, i2, 2, 3) || isAlpha(charSequence, i, i2, 5, 8)) {
            return true;
        }
        return (i2 - i) + 1 == 4 && charSequence.charAt(i) == 'r' && charSequence.charAt(i + 1) == 'o' && charSequence.charAt(i + 2) == 'o' && charSequence.charAt(i + 3) == 't';
    }

    public static boolean isExtensionSingleton(CharSequence charSequence, int i, int i2) {
        return isAlphaNum(charSequence, i, i2, 1, 1);
    }

    public static boolean isUnicodeScriptSubtag(CharSequence charSequence, int i, int i2) {
        return isAlpha(charSequence, i, i2, 4, 4);
    }

    public static boolean isUnicodeRegionSubtag(CharSequence charSequence, int i, int i2) {
        return isAlpha(charSequence, i, i2, 2, 2) || isDigit(charSequence, i, i2, 3, 3);
    }

    public static boolean isUnicodeVariantSubtag(CharSequence charSequence, int i, int i2) {
        return isAlphaNum(charSequence, i, i2, 5, 8) || isDigitAlphanum3(charSequence, i, i2);
    }

    public static boolean isUnicodeExtensionAttribute(CharSequence charSequence, int i, int i2) {
        return isAlphaNum(charSequence, i, i2, 3, 8);
    }

    public static boolean isUnicodeExtensionKey(CharSequence charSequence, int i, int i2) {
        return i2 == i + 1 && isASCIILetterOrDigit(charSequence.charAt(i)) && isASCIILetter(charSequence.charAt(i2));
    }

    public static boolean isUnicodeExtensionKeyTypeItem(CharSequence charSequence, int i, int i2) {
        return isAlphaNum(charSequence, i, i2, 3, 8);
    }

    public static boolean isTranformedExtensionTKey(CharSequence charSequence, int i, int i2) {
        return i2 == i + 1 && isASCIILetter(charSequence.charAt(i)) && isASCIIDigit(charSequence.charAt(i2));
    }

    public static boolean isTranformedExtensionTValueItem(CharSequence charSequence, int i, int i2) {
        return isAlphaNum(charSequence, i, i2, 3, 8);
    }

    public static boolean isPrivateUseExtension(CharSequence charSequence, int i, int i2) {
        return isAlphaNum(charSequence, i, i2, 1, 8);
    }

    public static boolean isOtherExtension(CharSequence charSequence, int i, int i2) {
        return isAlphaNum(charSequence, i, i2, 2, 8);
    }
}
