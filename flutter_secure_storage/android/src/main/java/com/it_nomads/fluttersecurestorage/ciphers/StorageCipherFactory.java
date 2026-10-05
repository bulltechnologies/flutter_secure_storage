package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;

import com.it_nomads.fluttersecurestorage.FlutterSecureStorageConfig;
import com.it_nomads.fluttersecurestorage.NamespacedConfigSource;
import com.it_nomads.fluttersecurestorage.CheckedPreferences;

import javax.crypto.Cipher;

public class StorageCipherFactory {
    private static final String ELEMENT_PREFERENCES_ALGORITHM_PREFIX = "FlutterSecureSAlgorithm";
    private static final String ELEMENT_PREFERENCES_ALGORITHM_KEY = ELEMENT_PREFERENCES_ALGORITHM_PREFIX + "Key";
    private static final String ELEMENT_PREFERENCES_ALGORITHM_STORAGE = ELEMENT_PREFERENCES_ALGORITHM_PREFIX + "Storage";
    private static final KeyCipherAlgorithm DEFAULT_KEY_ALGORITHM = KeyCipherAlgorithm.RSA_ECB_PKCS1Padding;
    private static final StorageCipherAlgorithm DEFAULT_STORAGE_ALGORITHM = StorageCipherAlgorithm.AES_CBC_PKCS7Padding;

    private final KeyCipherAlgorithm savedKeyAlgorithm;
    private final StorageCipherAlgorithm savedStorageAlgorithm;
    private final KeyCipherAlgorithm currentKeyAlgorithm;
    private final StorageCipherAlgorithm currentStorageAlgorithm;
    private final boolean assumedSavedAlgorithms;
    private final FlutterSecureStorageConfig config;

    public StorageCipherFactory(NamespacedConfigSource configSource, String keyCipherAlgorithm, String storageCipherAlgorithm, FlutterSecureStorageConfig config) {
        this.config = config;
        final String savedKeyCipherAlgorithm = configSource.getString(ELEMENT_PREFERENCES_ALGORITHM_KEY, null);
        final String savedStorageCipherAlgorithm = configSource.getString(ELEMENT_PREFERENCES_ALGORITHM_STORAGE, null);
        this.assumedSavedAlgorithms = savedKeyCipherAlgorithm == null || savedStorageCipherAlgorithm == null;

        if (savedKeyCipherAlgorithm == null || savedStorageCipherAlgorithm == null) {
            // Migration from v9.2.4 or v10.0.0-beta.4:
            // No algorithm markers exist in SharedPreferences, which means the data was encrypted
            // with the historical v9.2.4 defaults. We must use these defaults to decrypt the old
            // data, even if the current config specifies different algorithms.
            // After successful decryption, the data will be re-encrypted with current algorithms
            // (if they differ) via the migration flow in handleKeyMismatch().
            savedKeyAlgorithm = DEFAULT_KEY_ALGORITHM;        // RSA_ECB_PKCS1Padding
            savedStorageAlgorithm = DEFAULT_STORAGE_ALGORITHM; // AES_CBC_PKCS7Padding
        } else {
            savedKeyAlgorithm = KeyCipherAlgorithm.fromString(savedKeyCipherAlgorithm);
            savedStorageAlgorithm = StorageCipherAlgorithm.fromString(savedStorageCipherAlgorithm);
        }

        final StorageCipherAlgorithm currentStorageAlgorithmTmp = StorageCipherAlgorithm.fromString(storageCipherAlgorithm);
        currentStorageAlgorithm = (currentStorageAlgorithmTmp.minVersionCode <= Build.VERSION.SDK_INT) ? currentStorageAlgorithmTmp : DEFAULT_STORAGE_ALGORITHM;

        // Set current key algorithm with version check
        final KeyCipherAlgorithm currentKeyAlgorithmTmp = KeyCipherAlgorithm.fromString(keyCipherAlgorithm);
        currentKeyAlgorithm = (currentKeyAlgorithmTmp.minVersionCode <= Build.VERSION.SDK_INT) ? currentKeyAlgorithmTmp : DEFAULT_KEY_ALGORITHM;

        if (savedKeyCipherAlgorithm == null || savedStorageCipherAlgorithm == null) {
            // Don't write algorithm markers during migrateWithBackup
            // (the migration flow writes them at step 7 after success).
            if (!config.shouldMigrateWithBackup()) {
                final SharedPreferences.Editor source = configSource.edit();
                storeCurrentAlgorithms(source);
                source.apply();
            }
        }
    }

    public boolean requiresReEncryption() {
        return savedKeyAlgorithm != currentKeyAlgorithm || savedStorageAlgorithm != currentStorageAlgorithm;
    }

    /** True when there were no markers, so the saved algorithms are a guess. */
    public boolean assumedSavedAlgorithms() {
        return assumedSavedAlgorithms;
    }

    public boolean changedKeyAlgorithm() {
        return savedKeyAlgorithm != currentKeyAlgorithm;
    }

    public StorageCipher getSavedStorageCipher(Context context, Cipher cipher) throws Exception {
        final KeyCipher keyCipher = savedKeyAlgorithm.keyCipher.apply(context, config);
        return createStorageCipher(context, keyCipher, cipher, savedStorageAlgorithm);
    }

    public StorageCipher getCurrentStorageCipher(Context context, Cipher cipher) throws Exception {
        final KeyCipher keyCipher = currentKeyAlgorithm.keyCipher.apply(context, config);
        StorageCipher result = createStorageCipher(context, keyCipher, cipher, currentStorageAlgorithm);
        if (config.mayCreateKeys()) certifyRootFamily(context);
        return result;
    }

    /**
     * Whether the current storage cipher can decrypt the given ciphertext.
     * Always false for KeyStore/biometric ciphers, which need an authenticated
     * cipher.
     */
    public boolean currentCipherDecrypts(Context context, byte[] ciphertext) {
        try {
            getCurrentStorageCipher(context, null).decrypt(ciphertext);
            return true;
        } catch (Throwable t) {
            if (t instanceof VirtualMachineError) {
                throw (VirtualMachineError) t;
            }
            return false;
        }
    }

    /**
     * Dynamically selects the appropriate StorageCipher implementation based on
     * the KeyCipher type and StorageCipherAlgorithm.
     */
    /* package */ StorageCipher createStorageCipher(Context context, KeyCipher keyCipher,
                                               Cipher cipher, StorageCipherAlgorithm algorithm) throws Exception {
        // For AES_GCM_NoPadding, choose implementation based on KeyCipher type
        if (algorithm == StorageCipherAlgorithm.AES_GCM_NoPadding) {
            if (isKeyStoreKeyCipher(keyCipher)) {
                // Use KeyStore-based implementation (biometric/PIN auth capable)
                return new StorageCipherImplementationAES23(context, keyCipher, cipher, config);
            } else {
                // Use RSA-wrapped implementation (standard secure storage)
                return new StorageCipherImplementationGCM(context, keyCipher, cipher, config);
            }
        }

        // For other algorithms, use the function from enum
        if (algorithm.storageCipher == null) {
            throw new Exception("No implementation available for algorithm: " + algorithm.name());
        }
        return algorithm.storageCipher.apply(context, keyCipher, cipher, config);
    }

    /**
     * Checks if the KeyCipher uses KeyStore (AES) vs RSA wrapping.
     */
    private boolean isKeyStoreKeyCipher(KeyCipher keyCipher) {
        return keyCipher instanceof KeyCipherImplementationAES23;
    }

    public KeyCipher getCurrentKeyCipher(Context context) throws Exception {
        return currentKeyAlgorithm.keyCipher.apply(context, config);
    }

    public KeyCipher getSavedKeyCipher(Context context) throws Exception {
        return savedKeyAlgorithm.keyCipher.apply(context, config);
    }

    /**
     * The saved key algorithm resolved at construction time. Prefer this over re-reading
     * readSavedKeyAlgorithm(configSource) afterwards, since the constructor may have already
     * written the current markers there.
     */
    public KeyCipherAlgorithm getSavedKeyAlgorithm() {
        return savedKeyAlgorithm;
    }

    public KeyCipherAlgorithm getCurrentKeyAlgorithm() {
        return currentKeyAlgorithm;
    }

    public StorageCipherAlgorithm getSavedStorageAlgorithm() { return savedStorageAlgorithm; }
    public StorageCipherAlgorithm getCurrentStorageAlgorithm() { return currentStorageAlgorithm; }

    /** Explicit existing/target capabilities prevent a recovery read from
     * creating or replacing a key and keep successor slots isolated. */
    public StorageCipher forGeneration(Context context, KeyCipherAlgorithm keyAlgorithm,
            StorageCipherAlgorithm storageAlgorithm, String generation, boolean mayCreate) throws Exception {
        FlutterSecureStorageConfig generationConfig = config.forRootGeneration(generation, mayCreate);
        KeyCipher keyCipher = keyAlgorithm.keyCipher.apply(context, generationConfig);
        StorageCipher result;
        if (storageAlgorithm == StorageCipherAlgorithm.AES_GCM_NoPadding) {
            if (keyCipher instanceof KeyCipherImplementationAES23) {
                throw new IllegalStateException("Ordinary migration cannot change authentication policy");
            }
            result = new StorageCipherImplementationGCM(context, keyCipher, null, generationConfig);
        } else {
            result = storageAlgorithm.storageCipher.apply(context, keyCipher, null, generationConfig);
        }
        if (mayCreate) {
            // A previous failed commit may have left a generated slot in RAM.
            // Certify the whole wrapping family even when the constructor loaded
            // that slot rather than generating it on this retry.
            certifyRootFamily(context);
        }
        return result;
    }

    private void certifyRootFamily(Context context) {
        SharedPreferences roots = context.getSharedPreferences(config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
        CheckedPreferences.commit(roots, roots.edit());
    }

    public void retireGeneration(Context context, KeyCipherAlgorithm keyAlgorithm,
            StorageCipherAlgorithm storageAlgorithm, String generation) throws Exception {
        // Legacy global aliases/slots may be shared with another data family.
        if (generation == null && !config.hasStorageNamespace()) return;
        FlutterSecureStorageConfig source = config.forRootGeneration(generation, false);
        if (keyAlgorithm == KeyCipherAlgorithm.AES_GCM_NoPadding) throw new IllegalStateException("Not an ordinary source");
        String algorithmAlias = keyAlgorithm == KeyCipherAlgorithm.RSA_ECB_PKCS1Padding
                ? ".FlutterSecureStoragePluginKey" : ".FlutterSecureStoragePluginKeyOAEP";
        java.security.KeyStore store = java.security.KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        String alias = context.getPackageName() + algorithmAlias + source.getKeyAliasSuffix();
        store.deleteEntry(alias);
        if (store.containsAlias(alias)) throw new IllegalStateException("Source alias retirement was not verified");
        SharedPreferences roots = context.getSharedPreferences(config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
        SharedPreferences.Editor remove = roots.edit();
        if (storageAlgorithm == StorageCipherAlgorithm.AES_CBC_PKCS7Padding) {
            remove.remove(source.rootSlot(StorageCipherImplementationAES18.WRAPPED_KEY_PREF));
        } else {
            remove.remove(source.rootSlot(StorageCipherImplementationGCM.WRAPPED_KEY_PREF))
                    .remove(source.rootSlot(StorageCipherImplementationGCM.LEGACY_V9_KEY));
        }
        CheckedPreferences.commit(roots, remove);
    }

    public void storeCurrentAlgorithms(SharedPreferences.Editor editor) {
        editor.putString(ELEMENT_PREFERENCES_ALGORITHM_KEY, currentKeyAlgorithm.name());
        editor.putString(ELEMENT_PREFERENCES_ALGORITHM_STORAGE, currentStorageAlgorithm.name());
    }

    /** Reads the saved key-cipher marker, or null if none was ever written. */
    public static String readSavedKeyAlgorithm(NamespacedConfigSource configSource) {
        return configSource.getString(ELEMENT_PREFERENCES_ALGORITHM_KEY, null);
    }

    /**
     * Copies algorithm markers from the data prefs, where v9 stored them, into
     * the config source, where v10+ looks. No-op if the config source already
     * has markers or the data prefs have none. Returns true if it copied.
     */
    public static boolean adoptLegacyMarkers(NamespacedConfigSource configSource, SharedPreferences dataPrefs) {
        if (configSource.getString(ELEMENT_PREFERENCES_ALGORITHM_KEY, null) != null
                && configSource.getString(ELEMENT_PREFERENCES_ALGORITHM_STORAGE, null) != null) {
            return false;
        }
        final String key = dataPrefs.getString(ELEMENT_PREFERENCES_ALGORITHM_KEY, null);
        final String storage = dataPrefs.getString(ELEMENT_PREFERENCES_ALGORITHM_STORAGE, null);
        if (key == null || storage == null) {
            return false;
        }
        SharedPreferences.Editor adopted = configSource.edit()
                .putString(ELEMENT_PREFERENCES_ALGORITHM_KEY, key)
                .putString(ELEMENT_PREFERENCES_ALGORITHM_STORAGE, storage);
        configSource.commit(adopted);
        return true;
    }
}
