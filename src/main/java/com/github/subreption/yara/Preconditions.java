package com.github.subreption.yara;

public class Preconditions {
    public static void checkArgument(boolean value) {
        if (!value) {
            throw new IllegalArgumentException();
        }
    }

    public static void checkState(boolean value) {
        if (!value) {
            throw new IllegalStateException();
        }
    }
}
