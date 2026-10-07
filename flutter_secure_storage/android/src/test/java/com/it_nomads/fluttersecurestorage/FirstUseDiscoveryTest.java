package com.it_nomads.fluttersecurestorage;

import android.content.Context;
import android.content.SharedPreferences;
import android.hardware.biometrics.BiometricPrompt;
import android.os.CancellationSignal;
import com.it_nomads.fluttersecurestorage.ciphers.KeyCipher;
import com.it_nomads.fluttersecurestorage.ciphers.StorageCipher;
import com.it_nomads.fluttersecurestorage.ciphers.StorageCipherFactory;
import com.it_nomads.fluttersecurestorage.ciphers.StorageCipherImplementationGCM;
import com.it_nomads.fluttersecurestorage.crypto.EncryptedSharedPreferences;
import com.it_nomads.fluttersecurestorage.crypto.MasterKey;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executor;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;
import org.robolectric.annotation.Implementation;
import org.robolectric.annotation.Implements;
import org.robolectric.annotation.RealObject;
import org.robolectric.util.ReflectionHelpers;
import org.robolectric.shadow.api.Shadow;
import static org.junit.Assert.*;

/** Exercises real initialize/read/write/recreate paths. Only platform key
 * wrapping is synthetic; AES-GCM records and preference ownership are real.
 * The ESP shadow models create()'s documented keyset creation side effect so
 * discovery cannot accidentally pass merely because a host lacks KeyStore. */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34, shadows = {FirstUseDiscoveryTest.MasterKeyBuilderShadow.class,
        FirstUseDiscoveryTest.EncryptedPreferencesShadow.class,
        FirstUseDiscoveryTest.PromptShadow.class,
        FirstUseDiscoveryTest.CheckedPreferencesShadow.class,
        FirstUseDiscoveryTest.CipherFactoryShadow.class})
public class FirstUseDiscoveryTest {
    private static final String FAMILY = "firstUseDiscovery";
    private static final String KEY_KEYSET = "__androidx_security_crypto_encrypted_prefs_key_keyset__";
    private static final String VALUE_KEYSET = "__androidx_security_crypto_encrypted_prefs_value_keyset__";
    private static final String KEY_ALGORITHM = "FlutterSecureSAlgorithmKey";
    private static final String DATA_ALGORITHM = "FlutterSecureSAlgorithmStorage";
    private static final String CURRENT_KEY = "RSA_ECB_OAEPwithSHA_256andMGF1Padding";
    private static final String CURRENT_DATA = "AES_GCM_NoPadding";
    private Context context;
    private FlutterSecureStorageConfig options;
    private SharedPreferences data;
    private NamespacedConfigSource control;

    @Before public void setUp() {
        context = RuntimeEnvironment.getApplication();
        Map<String, Object> raw = new HashMap<>();
        raw.put("storageNamespace", FAMILY);
        raw.put("resetOnError", "false");
        raw.put("migrateOnAlgorithmChange", "false");
        raw.put("migrateWithBackup", "false");
        options = new FlutterSecureStorageConfig(raw);
        data = context.getSharedPreferences(FAMILY, Context.MODE_PRIVATE);
        control = new NamespacedConfigSource(context, FAMILY);
        EncryptedPreferencesShadow.creations = 0;
        CipherFactoryShadow.rootLoads = 0;
        PromptShadow.prompts = 0;
        PromptShadow.pending = null;
        CheckedPreferencesShadow.config = control.scopedPreferences();
        CheckedPreferencesShadow.configCommits = 0;
        CheckedPreferencesShadow.failNextConfigCommit = false;
        CheckedPreferencesShadow.confirmedConfig = new HashMap<>();
    }

    private Exception initialize(FlutterSecureStorage storage) {
        final boolean[] completed = {false};
        final Exception[] error = {null};
        storage.initialize(options, new SecurePreferencesCallback<Void>() {
            public void onSuccess(Void ignored) { completed[0] = true; }
            public void onError(Exception failure) { completed[0] = true; error[0] = failure; }
        });
        assertTrue("Ordinary first use must complete without authentication", completed[0]);
        return error[0];
    }

    @Test public void freshReadOpensCurrentStorageWithoutCreatingLegacyKeysets() throws Exception {
        FlutterSecureStorage storage = new FlutterSecureStorage(context);

        assertNull(initialize(storage));
        assertNull(storage.read(storage.addPrefixToKey("absent")));
        assertTrue(storage.readAll().isEmpty());
        assertEquals(0, EncryptedPreferencesShadow.creations);
        assertFalse(data.contains(KEY_KEYSET));
        assertFalse(data.contains(VALUE_KEYSET));
        assertEquals(CURRENT_KEY, control.getString(KEY_ALGORITHM, null));
        assertEquals(CURRENT_DATA, control.getString(DATA_ALGORITHM, null));

        String key = storage.addPrefixToKey("fixture");
        storage.write(key, "preserved value");
        Map<String, ?> before = new HashMap<>(data.getAll());
        FlutterSecureStorage recreated = new FlutterSecureStorage(context);
        assertNull(initialize(recreated));
        assertEquals("preserved value", recreated.read(key));
        assertEquals(before, data.getAll());
        assertEquals(0, EncryptedPreferencesShadow.creations);
    }

    @Test public void preexistingLegacyKeysetsAreNotRelabeledOnRepeatedAttempts() {
        for (boolean currentMarkers : new boolean[] {false, true}) {
            for (int keysets = 1; keysets <= 3; keysets++) {
                data.edit().clear().commit();
                control.scopedPreferences().edit().clear().commit();
                SharedPreferences.Editor seed = data.edit();
                if ((keysets & 1) != 0) seed.putString(KEY_KEYSET, "opaque original keyset");
                if ((keysets & 2) != 0) seed.putString(VALUE_KEYSET, "opaque original keyset");
                seed.commit();
                if (currentMarkers) control.commit(control.edit()
                        .putString(KEY_ALGORITHM, CURRENT_KEY).putString(DATA_ALGORITHM, CURRENT_DATA));
                Map<String, ?> beforeData = new HashMap<>(data.getAll());
                Map<String, ?> beforeControl = new HashMap<>(control.scopedPreferences().getAll());
                SharedPreferences roots = context.getSharedPreferences(options.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
                Map<String, ?> beforeRoots = new HashMap<>(roots.getAll());
                for (int attempt = 0; attempt < 2; attempt++) {
                    assertNotNull("Existing opaque/partial legacy state requires preserved recovery",
                            initialize(new FlutterSecureStorage(context)));
                    assertEquals(beforeData, data.getAll());
                    assertEquals(beforeControl, control.scopedPreferences().getAll());
                    assertEquals(beforeRoots, roots.getAll());
                }
            }
        }
        assertEquals(0, EncryptedPreferencesShadow.creations);
    }

    @Test public void rejectedOrdinaryCiphertextDoesNotGainCurrentAlgorithmMarkers() {
        for (boolean partialMarker : new boolean[] {false, true}) {
            control.scopedPreferences().edit().clear().commit();
            data.edit().clear().putString(options.getSharedPreferencesKeyPrefix() + "_fixture", "unreadable source").commit();
            if (partialMarker) control.commit(control.edit().putString(KEY_ALGORITHM, "RSA_ECB_PKCS1Padding"));
            Map<String, ?> beforeData = new HashMap<>(data.getAll());
            Map<String, ?> beforeControl = new HashMap<>(control.scopedPreferences().getAll());
            for (int attempt = 0; attempt < 2; attempt++) {
                assertNotNull(initialize(new FlutterSecureStorage(context)));
                assertEquals(beforeData, data.getAll());
                assertEquals(beforeControl, control.scopedPreferences().getAll());
            }
        }
        assertEquals(0, EncryptedPreferencesShadow.creations);
    }

    @Test public void orphanedOpaquePayloadWithoutLegacyKeysetsIsNotAnEmptyFamily() {
        data.edit().putString("opaque legacy identifier", "opaque ciphertext").commit();
        Map<String, ?> before = new HashMap<>(data.getAll());
        SharedPreferences roots = context.getSharedPreferences(options.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
        for (int attempt = 0; attempt < 2; attempt++) {
            assertNotNull(initialize(new FlutterSecureStorage(context)));
            assertEquals(before, data.getAll());
            assertTrue(control.scopedPreferences().getAll().isEmpty());
            assertTrue(roots.getAll().isEmpty());
        }
        assertEquals(0, CipherFactoryShadow.rootLoads);
        assertEquals(0, EncryptedPreferencesShadow.creations);
    }

    @Test public void ordinaryRecordsKeepWorkingBesideHistoricalProbeKeysets() throws Exception {
        FlutterSecureStorage storage = new FlutterSecureStorage(context);
        assertNull(initialize(storage));
        String key = storage.addPrefixToKey("fixture");
        storage.write(key, "ordinary record");
        data.edit().putString(KEY_KEYSET, "historical probe keyset")
                .putString(VALUE_KEYSET, "historical probe keyset").commit();
        Map<String, ?> before = new HashMap<>(data.getAll());

        FlutterSecureStorage recreated = new FlutterSecureStorage(context);
        assertNull(initialize(recreated));
        assertEquals("ordinary record", recreated.read(key));
        assertEquals(before, data.getAll());
        assertEquals(0, EncryptedPreferencesShadow.creations);
    }

    @Test public void authenticatedCurrentRecordsRecoverMissingMarkers() throws Exception {
        FlutterSecureStorage storage = new FlutterSecureStorage(context);
        assertNull(initialize(storage));
        String key = storage.addPrefixToKey("fixture");
        storage.write(key, "ordinary record");
        control.scopedPreferences().edit().clear().commit();
        Map<String, ?> before = new HashMap<>(data.getAll());

        FlutterSecureStorage recreated = new FlutterSecureStorage(context);
        assertNull(initialize(recreated));
        assertEquals("ordinary record", recreated.read(key));
        assertEquals(CURRENT_KEY, control.getString(KEY_ALGORITHM, null));
        assertEquals(CURRENT_DATA, control.getString(DATA_ALGORITHM, null));
        assertEquals(before, data.getAll());
        assertEquals(0, EncryptedPreferencesShadow.creations);
    }

    @Test public void emptiedOrdinaryFamilyReopensUsingItsExistingRootAndKeepsSentinels() throws Exception {
        FlutterSecureStorage storage = new FlutterSecureStorage(context);
        assertNull(initialize(storage));
        String key = storage.addPrefixToKey("fixture");
        storage.write(key, "deleted record");
        storage.delete(key);
        assertTrue(data.getAll().isEmpty());
        data.edit().putString(KEY_KEYSET, "historical probe keyset")
                .putString(VALUE_KEYSET, "historical probe keyset").commit();
        SharedPreferences roots = context.getSharedPreferences(options.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
        Map<String, ?> beforeRoots = new HashMap<>(roots.getAll());
        assertFalse(beforeRoots.isEmpty());
        Map<String, ?> beforeControl = new HashMap<>(control.scopedPreferences().getAll());

        for (String sentinel : new String[] {"__fss_checked_commit_v1__", "__index_checked_commit_v1__"}) {
            data.edit().putString(sentinel, "interrupted checked commit").commit();
            Map<String, ?> beforeData = new HashMap<>(data.getAll());
            FlutterSecureStorage recreated = new FlutterSecureStorage(context);
            assertNull(initialize(recreated));
            assertTrue(recreated.readAll().isEmpty());
            assertEquals(beforeData, data.getAll());
            assertEquals(beforeRoots, roots.getAll());
            assertEquals(beforeControl, control.scopedPreferences().getAll());
        }
        assertEquals(0, EncryptedPreferencesShadow.creations);
    }

    @Test public void explicitLegacyBackendStillInitializesLegacyStorage() {
        Map<String, Object> raw = new HashMap<>();
        raw.put("storageNamespace", FAMILY);
        raw.put("encryptedSharedPreferences", "true");
        raw.put("migrateOnAlgorithmChange", "false");
        raw.put("migrateWithBackup", "false");
        raw.put("resetOnError", "false");
        options = new FlutterSecureStorageConfig(raw);

        assertNull(initialize(new FlutterSecureStorage(context)));
        assertEquals(1, EncryptedPreferencesShadow.creations);
        assertEquals(0, CipherFactoryShadow.rootLoads);
        assertTrue(data.contains(KEY_KEYSET));
        assertTrue(data.contains(VALUE_KEYSET));
        assertTrue(control.scopedPreferences().getAll().isEmpty());
    }

    @Test public void freshBiometricFamilyRequiresAuthBeforeWriteAndAfterRecreation() {
        Map<String, Object> raw = new HashMap<>();
        raw.put("storageNamespace", FAMILY);
        raw.put("keyCipherAlgorithm", "AES_GCM_NoPadding");
        raw.put("requireBiometricsPerOperation", "true");
        raw.put("migrateOnAlgorithmChange", "false");
        raw.put("migrateWithBackup", "false");
        raw.put("resetOnError", "false");
        options = new FlutterSecureStorageConfig(raw);
        FlutterSecureStorage storage = new FlutterSecureStorage(context) {
            @Override public boolean isDeviceSecure() { return true; }
        };

        assertNull(initialize(storage));
        assertNull(ReflectionHelpers.getField(storage, "storageCipher"));
        assertEquals(0, CipherFactoryShadow.rootLoads);
        assertEquals(0, EncryptedPreferencesShadow.creations);
        assertTrue(control.scopedPreferences().getAll().isEmpty());
        assertEquals(0, PromptShadow.prompts);

        String key = storage.addPrefixToKey("protected");
        TestCallback<Void> cancelled = new TestCallback<>();
        storage.write(key, "protected value", cancelled);
        assertFalse(cancelled.completed);
        assertEquals(1, PromptShadow.prompts);
        assertTrue(data.getAll().isEmpty());
        assertTrue(control.scopedPreferences().getAll().isEmpty());
        assertEquals(0, CipherFactoryShadow.rootLoads);
        PromptShadow.cancel();
        assertTrue(cancelled.completed);
        assertNotNull(cancelled.error);
        assertTrue(control.scopedPreferences().getAll().isEmpty());

        TestCallback<Void> written = new TestCallback<>();
        storage.write(key, "protected value", written);
        assertFalse(written.completed);
        PromptShadow.succeed();
        assertTrue(written.completed);
        assertNull(written.error);
        assertEquals("AES_GCM_NoPadding", control.getString(KEY_ALGORITHM, null));
        assertEquals(CURRENT_DATA, control.getString(DATA_ALGORITHM, null));
        assertEquals(1, CipherFactoryShadow.rootLoads);
        // One marker publication plus writeUnsafe's existing recovery-authority barrier.
        assertEquals(2, CheckedPreferencesShadow.configCommits);

        TestCallback<String> sameSessionRead = new TestCallback<>();
        storage.read(key, sameSessionRead);
        assertFalse(sameSessionRead.completed);
        PromptShadow.succeed();
        assertNull(sameSessionRead.error);
        assertEquals("protected value", sameSessionRead.value);
        assertEquals(2, CheckedPreferencesShadow.configCommits);

        FlutterSecureStorage recreated = new FlutterSecureStorage(context) {
            @Override public boolean isDeviceSecure() { return true; }
        };
        assertNull(initialize(recreated));
        assertNull(ReflectionHelpers.getField(recreated, "storageCipher"));
        TestCallback<String> read = new TestCallback<>();
        recreated.read(key, read);
        assertFalse(read.completed);
        assertEquals(4, PromptShadow.prompts);
        PromptShadow.succeed();
        assertTrue(read.completed);
        assertNull(read.error);
        assertEquals("protected value", read.value);
        assertEquals(2, CheckedPreferencesShadow.configCommits);
    }

    @Test public void existingMarkerlessBiometricDataIsNeverRelabeledByTheFreshPath() {
        Map<String, Object> raw = new HashMap<>();
        raw.put("storageNamespace", FAMILY);
        raw.put("keyCipherAlgorithm", "AES_GCM_NoPadding");
        raw.put("requireBiometricsPerOperation", "true");
        raw.put("migrateOnAlgorithmChange", "false");
        raw.put("migrateWithBackup", "false");
        raw.put("resetOnError", "false");
        options = new FlutterSecureStorageConfig(raw);
        data.edit().putString(options.getSharedPreferencesKeyPrefix() + "_fixture", "opaque source").commit();
        Map<String, ?> before = new HashMap<>(data.getAll());

        for (int attempt = 0; attempt < 2; attempt++) {
            assertNotNull(initialize(new FlutterSecureStorage(context)));
            assertEquals(before, data.getAll());
            assertTrue(control.scopedPreferences().getAll().isEmpty());
        }
        assertEquals(0, CipherFactoryShadow.rootLoads);
        assertEquals(0, EncryptedPreferencesShadow.creations);
    }

    @Test public void failedMarkerCommitSameProviderRetryCertifiesLabelsBeforeWriting() {
        assertFailedMarkerRetry(false);
    }

    @Test public void failedMarkerCommitNewProviderRetryCertifiesLabelsBeforeWriting() {
        assertFailedMarkerRetry(true);
    }

    private void assertFailedMarkerRetry(boolean recreateProvider) {
        Map<String, Object> raw = new HashMap<>();
        raw.put("storageNamespace", FAMILY);
        raw.put("keyCipherAlgorithm", "AES_GCM_NoPadding");
        raw.put("requireBiometricsPerOperation", "true");
        raw.put("migrateOnAlgorithmChange", "false");
        raw.put("migrateWithBackup", "false");
        raw.put("resetOnError", "false");
        options = new FlutterSecureStorageConfig(raw);
        FlutterSecureStorage storage = secureDeviceStorage();
        assertNull(initialize(storage));
        String key = storage.addPrefixToKey("protected");
        TestCallback<Void> failedMarkers = new TestCallback<>();
        storage.write(key, "protected value", failedMarkers);
        CheckedPreferencesShadow.failNextConfigCommit = true;
        PromptShadow.succeed();
        assertTrue(failedMarkers.completed);
        assertNotNull(failedMarkers.error);
        assertEquals("AES_GCM_NoPadding", control.getString(KEY_ALGORITHM, null));
        assertTrue(CheckedPreferencesShadow.confirmedConfig.isEmpty());
        assertTrue(data.getAll().isEmpty());

        if (recreateProvider) {
            storage = secureDeviceStorage();
            assertNull(initialize(storage));
        }
        TestCallback<String> emptyRead = new TestCallback<>();
        storage.read(key, emptyRead);
        PromptShadow.succeed();
        assertTrue(emptyRead.completed);
        assertNull(emptyRead.error);
        assertNull(emptyRead.value);
        // Reading no new data does not certify the prior failed label write.
        assertTrue(CheckedPreferencesShadow.confirmedConfig.isEmpty());
        assertEquals(1, CheckedPreferencesShadow.configCommits);

        TestCallback<Void> failedAuthority = new TestCallback<>();
        storage.write(key, "protected value", failedAuthority);
        CheckedPreferencesShadow.failNextConfigCommit = true;
        PromptShadow.succeed();
        assertTrue(failedAuthority.completed);
        assertNotNull(failedAuthority.error);
        assertTrue(data.getAll().isEmpty());
        assertTrue(CheckedPreferencesShadow.confirmedConfig.isEmpty());

        TestCallback<Void> written = new TestCallback<>();
        storage.write(key, "protected value", written);
        PromptShadow.succeed();
        assertTrue(written.completed);
        assertNull(written.error);
        assertEquals("AES_GCM_NoPadding", CheckedPreferencesShadow.confirmedConfig.get(KEY_ALGORITHM));
        assertEquals(CURRENT_DATA, CheckedPreferencesShadow.confirmedConfig.get(DATA_ALGORITHM));
        assertEquals(3, CheckedPreferencesShadow.configCommits);

        FlutterSecureStorage recreated = secureDeviceStorage();
        assertNull(initialize(recreated));
        TestCallback<String> read = new TestCallback<>();
        recreated.read(key, read);
        PromptShadow.succeed();
        assertTrue(read.completed);
        assertNull(read.error);
        assertEquals("protected value", read.value);
        assertEquals(3, CheckedPreferencesShadow.configCommits);
    }

    private FlutterSecureStorage secureDeviceStorage() {
        return new FlutterSecureStorage(context) {
            @Override public boolean isDeviceSecure() { return true; }
        };
    }

    @Test public void opaqueEspPayloadBesideOrdinaryRecordsCannotBeHiddenByCurrentMarkers() throws Exception {
        FlutterSecureStorage storage = new FlutterSecureStorage(context);
        assertNull(initialize(storage));
        storage.write(storage.addPrefixToKey("fixture"), "ordinary record");
        data.edit().putString(KEY_KEYSET, "historical keyset")
                .putString(VALUE_KEYSET, "historical keyset")
                .putString("opaque encrypted ESP identifier", "opaque ciphertext").commit();
        Map<String, ?> beforeData = new HashMap<>(data.getAll());
        Map<String, ?> beforeControl = new HashMap<>(control.scopedPreferences().getAll());
        int rootLoads = CipherFactoryShadow.rootLoads;
        for (int attempt = 0; attempt < 2; attempt++) {
            assertNotNull(initialize(new FlutterSecureStorage(context)));
            assertEquals(beforeData, data.getAll());
            assertEquals(beforeControl, control.scopedPreferences().getAll());
        }
        assertEquals(rootLoads, CipherFactoryShadow.rootLoads);
        assertEquals(0, EncryptedPreferencesShadow.creations);
    }

    @Implements(MasterKey.Builder.class)
    public static class MasterKeyBuilderShadow {
        @Implementation protected MasterKey build() {
            return ReflectionHelpers.callConstructor(MasterKey.class,
                    ReflectionHelpers.ClassParameter.from(String.class, "synthetic-master-key"),
                    ReflectionHelpers.ClassParameter.from(Object.class, null));
        }
    }

    private static final class TestCallback<T> implements SecurePreferencesCallback<T> {
        boolean completed;
        T value;
        Exception error;
        public void onSuccess(T value) { this.value = value; completed = true; }
        public void onError(Exception error) { this.error = error; completed = true; }
    }

    @Implements(BiometricPrompt.class)
    public static class PromptShadow {
        static int prompts;
        static BiometricPrompt.CryptoObject crypto;
        static BiometricPrompt.AuthenticationCallback pending;
        @Implementation protected void authenticate(BiometricPrompt.CryptoObject crypto,
                CancellationSignal cancellation, Executor executor, BiometricPrompt.AuthenticationCallback callback) {
            prompts++;
            PromptShadow.crypto = crypto;
            pending = callback;
        }
        static void cancel() {
            pending.onAuthenticationError(5, "Fixture cancellation");
            pending = null;
        }
        static void succeed() {
            BiometricPrompt.AuthenticationResult result = ReflectionHelpers.callConstructor(
                    BiometricPrompt.AuthenticationResult.class,
                    ReflectionHelpers.ClassParameter.from(BiometricPrompt.CryptoObject.class, crypto),
                    ReflectionHelpers.ClassParameter.from(int.class, 2));
            pending.onAuthenticationSucceeded(result);
            pending = null;
        }
    }

    @Implements(CheckedPreferences.class)
    public static class CheckedPreferencesShadow {
        static SharedPreferences config;
        static int configCommits;
        static boolean failNextConfigCommit;
        // Track acknowledged snapshots separately from visible RAM state. The
        // failure fixture updates RAM, then refuses persistence confirmation.
        static Map<String, ?> confirmedConfig;
        @Implementation protected static void commit(SharedPreferences preferences, SharedPreferences.Editor editor) {
            if (preferences == config) {
                configCommits++;
                if (failNextConfigCommit) {
                    failNextConfigCommit = false;
                    editor.apply();
                    throw new IllegalStateException("Fixture persistence confirmation failed after RAM update");
                }
            }
            Shadow.directlyOn(CheckedPreferences.class, "commit",
                    ReflectionHelpers.ClassParameter.from(SharedPreferences.class, preferences),
                    ReflectionHelpers.ClassParameter.from(SharedPreferences.Editor.class, editor));
            if (preferences == config) confirmedConfig = new HashMap<>(preferences.getAll());
        }
    }

    @Implements(EncryptedSharedPreferences.class)
    public static class EncryptedPreferencesShadow {
        static int creations;
        @Implementation protected static SharedPreferences create(Context context, String name, MasterKey key,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme keyScheme,
                EncryptedSharedPreferences.PrefValueEncryptionScheme valueScheme) {
            creations++;
            SharedPreferences prefs = context.getSharedPreferences(name, Context.MODE_PRIVATE);
            SharedPreferences.Editor editor = prefs.edit();
            if (!prefs.contains(KEY_KEYSET)) editor.putString(KEY_KEYSET, "synthetic created keyset");
            if (!prefs.contains(VALUE_KEYSET)) editor.putString(VALUE_KEYSET, "synthetic created keyset");
            editor.commit();
            return context.getSharedPreferences(name + ".decrypted-fixture", Context.MODE_PRIVATE);
        }
    }

    @Implements(StorageCipherFactory.class)
    public static class CipherFactoryShadow {
        @RealObject StorageCipherFactory factory;
        static int rootLoads;
        @Implementation protected KeyCipher getCurrentKeyCipher(Context ignored) throws Exception {
            FlutterSecureStorageConfig options = ReflectionHelpers.getField(factory, "config");
            return new SyntheticKeyCipher(options.getPrefOptionKeyCipherAlgorithm().startsWith("AES_")
                    ? Cipher.getInstance("AES/GCM/NoPadding") : null);
        }
        @Implementation protected StorageCipher getCurrentStorageCipher(Context context, Cipher cipher) throws Exception {
            rootLoads++;
            FlutterSecureStorageConfig options = ReflectionHelpers.getField(factory, "config");
            return new StorageCipherImplementationGCM(context, new SyntheticKeyCipher(), cipher, options);
        }
    }

    private static final class SyntheticKeyCipher implements KeyCipher {
        private final Cipher cipher;
        SyntheticKeyCipher() { this(null); }
        SyntheticKeyCipher(Cipher cipher) { this.cipher = cipher; }
        public Cipher getCipher(Context ignored) { return cipher; }
        public void deleteKey() { throw new AssertionError("Discovery must not delete key material"); }
        public byte[] wrap(Key key) { return key.getEncoded(); }
        public Key unwrap(byte[] bytes, String algorithm) { return new SecretKeySpec(bytes, algorithm); }
    }
}
