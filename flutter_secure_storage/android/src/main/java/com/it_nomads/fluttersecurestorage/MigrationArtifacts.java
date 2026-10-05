package com.it_nomads.fluttersecurestorage;

import android.content.SharedPreferences;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import org.json.JSONObject;

/** Shared owned grammar. Logical-key deletion never grants family/root authority. */
public final class MigrationArtifacts {
    public static final String MANIFEST = "__fss_migration_v1";
    public static final String ACTIVE_GENERATION = "__fss_active_generation_v1";
    public static final String DELETED_PREFIX = "__fss_deleted_v1__";
    public static final String SOURCE_PREFIX = "__fss_source_v1__";
    public static final String GENERATION_SUFFIX = "__FSSGEN__";
    private static final ConcurrentHashMap<String, Object> LOCKS = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, AtomicLong> EPOCHS = new ConcurrentHashMap<>();
    private MigrationArtifacts() {}

    public static Object familyLock(String dataPrefsName) {
        if (dataPrefsName == null || dataPrefsName.isEmpty()) {
            throw new IllegalArgumentException("Invalid secure storage family");
        }
        return LOCKS.computeIfAbsent(dataPrefsName, unused -> new Object());
    }

    /** In-process cache invalidation, called under familyLock before a full
     * family erase. Durable erase/recovery authority remains on disk. */
    public static long invalidateFamily(String dataPrefsName) {
        familyLock(dataPrefsName);
        return EPOCHS.computeIfAbsent(dataPrefsName, unused -> new AtomicLong()).incrementAndGet();
    }

    public static long familyEpoch(String dataPrefsName) {
        familyLock(dataPrefsName);
        return EPOCHS.computeIfAbsent(dataPrefsName, unused -> new AtomicLong()).get();
    }

    public static boolean isGeneration(String generation) {
        return generation != null && generation.matches("[a-f0-9]{32}");
    }

    public static String sourceCopyKey(String generation, String canonicalKey) {
        if (!isGeneration(generation) || canonicalKey == null || canonicalKey.isEmpty()) {
            throw new IllegalArgumentException("Invalid migration artifact identity");
        }
        return SOURCE_PREFIX + generation + "__" + canonicalKey;
    }

    public static boolean isSourceCopyKeyFor(String physicalKey, String canonicalKey) {
        return canonicalKey != null && canonicalKey.equals(canonicalKeyFromSourceCopy(physicalKey));
    }

    public static String canonicalKeyFromSourceCopy(String physicalKey) {
        if (physicalKey == null || !physicalKey.startsWith(SOURCE_PREFIX)) return null;
        int end = SOURCE_PREFIX.length() + 32;
        return physicalKey.length() > end + 2
                && isGeneration(physicalKey.substring(SOURCE_PREFIX.length(), end))
                && physicalKey.startsWith("__", end)
                ? physicalKey.substring(end + 2) : null;
    }

    public static boolean isGenerationAliasFor(String alias, String packageName, String namespace) {
        if (alias == null || packageName == null) return false;
        String suffix = namespace == null ? "" : "." + namespace;
        for (String algorithm : new String[]{"FlutterSecureStoragePluginKey", "FlutterSecureStoragePluginKeyOAEP"}) {
            String base = packageName + "." + algorithm + suffix + GENERATION_SUFFIX;
            if (alias.startsWith(base) && isGeneration(alias.substring(base.length()))) return true;
        }
        return false;
    }

    /** Call under familyLock before removing canonical/recovery copies. This
     * suppression is finite and belongs only to the pending target generation. */
    public static void recordKeyDeletion(SharedPreferences scopedConfig, String canonicalKey) {
        String raw = scopedConfig.getString(MANIFEST, null);
        if (raw == null) return;
        try {
            JSONObject manifest = new JSONObject(raw);
            String generation = manifest.getString("generation");
            if (manifest.getInt("version") != 1 || !isGeneration(generation)) {
                throw new IllegalStateException("Unsupported migration authority");
            }
            CheckedPreferences.commit(scopedConfig,
                    scopedConfig.edit().putString(DELETED_PREFIX + canonicalKey, generation));
        } catch (RuntimeException error) {
            throw error;
        } catch (Exception error) {
            throw new IllegalStateException("Unreadable migration authority", error);
        }
    }
}
