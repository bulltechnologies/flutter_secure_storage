package com.it_nomads.fluttersecurestorage;

import android.content.SharedPreferences;
import java.util.UUID;

/** A same-value retry can otherwise report success after a failed commit changed
 * RAM only. Force a changed disk generation before acknowledging the boundary. */
public final class CheckedPreferences {
    private static final String BARRIER = "__fss_checked_commit_v1__";
    private CheckedPreferences() {}

    public static void commit(SharedPreferences preferences, SharedPreferences.Editor editor) {
        if (!editor.commit()
                || !preferences.edit().putString(BARRIER, UUID.randomUUID().toString()).commit()
                || !preferences.edit().remove(BARRIER).commit()) {
            throw new IllegalStateException("Secure storage persistence was not confirmed");
        }
    }
}
