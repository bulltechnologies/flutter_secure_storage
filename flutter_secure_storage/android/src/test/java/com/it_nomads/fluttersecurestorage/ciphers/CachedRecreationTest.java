package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import com.it_nomads.fluttersecurestorage.CheckedPreferences;
import com.it_nomads.fluttersecurestorage.FlutterSecureStorage;
import com.it_nomads.fluttersecurestorage.FlutterSecureStorageConfig;
import com.it_nomads.fluttersecurestorage.MigrationArtifacts;
import com.it_nomads.fluttersecurestorage.NamespacedConfigSource;
import com.it_nomads.fluttersecurestorage.OrdinaryMigration;
import com.it_nomads.fluttersecurestorage.SecurePreferencesCallback;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;
import static org.junit.Assert.*;

/** Actual cached plugin storage calls with synthetic roots/preferences. The
 * factory never accesses Android KeyStore or requests authentication. */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class CachedRecreationTest {
    private static final String FAMILY = "syntheticCachedRecreation";
    private static final String PREFIX = "syntheticPrefix", A = PREFIX + "_A", B = PREFIX + "_B";
    private static final String SOURCE_KEY = "RSA_ECB_PKCS1Padding";
    private static final String TARGET_KEY = "RSA_ECB_OAEPwithSHA_256andMGF1Padding";
    private static final String DATA = "AES_GCM_NoPadding";

    private static final class AesRoot implements StorageCipher {
        final SecretKeySpec root;
        AesRoot() {
            byte[] bytes = new byte[16]; new SecureRandom().nextBytes(bytes);
            root = new SecretKeySpec(bytes, "AES");
        }
        public byte[] encrypt(byte[] plaintext) throws Exception {
            byte[] iv = new byte[12]; new SecureRandom().nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, root, new GCMParameterSpec(128, iv));
            byte[] payload = cipher.doFinal(plaintext), result = new byte[iv.length + payload.length];
            System.arraycopy(iv, 0, result, 0, iv.length); System.arraycopy(payload, 0, result, iv.length, payload.length);
            return result;
        }
        public byte[] decrypt(byte[] bytes) throws Exception {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, root, new GCMParameterSpec(128, java.util.Arrays.copyOfRange(bytes, 0, 12)));
            return cipher.doFinal(java.util.Arrays.copyOfRange(bytes, 12, bytes.length));
        }
        public byte[] authenticateMigration(byte[] bytes) throws Exception { return MigrationAuthentication.sign(root, bytes); }
        public void deleteKey(Context ignored) { fail("Migration must retire explicit source identity"); }
    }

    private static final class Factory extends StorageCipherFactory {
        final Map<String, AesRoot> roots = new HashMap<>();
        boolean failCleanup = true;
        Factory(NamespacedConfigSource config, FlutterSecureStorageConfig options) {
            super(config, TARGET_KEY, DATA, options);
            roots.put(null, new AesRoot());
        }
        @Override public StorageCipher forGeneration(Context ignored, KeyCipherAlgorithm key,
                StorageCipherAlgorithm data, String generation, boolean mayCreate) {
            if (!roots.containsKey(generation)) {
                if (!mayCreate) throw new IllegalStateException("Synthetic source missing");
                roots.put(generation, new AesRoot());
            }
            return roots.get(generation);
        }
        @Override public void retireGeneration(Context ignored, KeyCipherAlgorithm key,
                StorageCipherAlgorithm data, String generation) {
            if (failCleanup) throw new IllegalStateException("Injected source cleanup failure");
            roots.remove(generation);
        }
    }

    private static void field(FlutterSecureStorage storage, String name, Object value) throws Exception {
        Field field = FlutterSecureStorage.class.getDeclaredField(name); field.setAccessible(true); field.set(storage, value);
    }
    private static String encode(byte[] value) { return Base64.encodeToString(value, Base64.NO_WRAP); }
    private static byte[] bytes(String value) { return value.getBytes(StandardCharsets.UTF_8); }

    @Test public void cachedDeleteAndRecreateCannotLoseAcknowledgedBytes() throws Exception {
        Context context = RuntimeEnvironment.getApplication();
        SharedPreferences data = context.getSharedPreferences(FAMILY, Context.MODE_PRIVATE);
        data.edit().clear().commit();
        NamespacedConfigSource config = new NamespacedConfigSource(context, FAMILY);
        config.scopedPreferences().edit().clear().putString("FlutterSecureSAlgorithmKey", SOURCE_KEY)
                .putString("FlutterSecureSAlgorithmStorage", DATA).commit();
        Map<String, Object> raw = new HashMap<>();
        raw.put("storageNamespace", FAMILY); raw.put("preferencesKeyPrefix", PREFIX);
        raw.put("migrateWithBackup", "true"); raw.put("resetOnError", "false");
        FlutterSecureStorageConfig options = new FlutterSecureStorageConfig(raw);
        Factory factory = new Factory(config, options);
        AesRoot source = factory.roots.get(null);
        CheckedPreferences.commit(data, data.edit().putString(A, encode(source.encrypt(bytes("old A"))))
                .putString(B, encode(source.encrypt(bytes("sibling B")))));
        OrdinaryMigration migration = new OrdinaryMigration(data, config, new OrdinaryMigration.Ciphers() {
            public StorageCipher load(String key, String algorithm, String generation, boolean mayCreate) {
                return factory.forGeneration(context, KeyCipherAlgorithm.fromString(key),
                        StorageCipherAlgorithm.fromString(algorithm), generation, mayCreate);
            }
            public void retire(String key, String algorithm, String generation) {
                factory.retireGeneration(context, KeyCipherAlgorithm.fromString(key),
                        StorageCipherAlgorithm.fromString(algorithm), generation);
            }
        }, PREFIX, SOURCE_KEY, DATA, TARGET_KEY, DATA);
        StorageCipher target = migration.run();
        assertTrue(config.contains(MigrationArtifacts.MANIFEST));

        FlutterSecureStorage storage = new FlutterSecureStorage(context);
        field(storage, "config", options.forRootGeneration(config.getString(MigrationArtifacts.ACTIVE_GENERATION, null), false));
        field(storage, "preferences", data); field(storage, "storageCipher", target);
        field(storage, "storageCipherFactory", factory);
        field(storage, "familyEpoch", MigrationArtifacts.familyEpoch(FAMILY));
        final boolean[] cached = {false};
        storage.initialize(options, new SecurePreferencesCallback<Void>() {
            public void onSuccess(Void ignored) { cached[0] = true; }
            public void onError(Exception error) { throw new AssertionError(error); }
        });
        assertTrue("Actual initialize must take its cached path", cached[0]);
        storage.delete(A);
        assertFalse(data.contains(A));
        assertThrows(IllegalStateException.class, () -> storage.write(A, "recreated A"));
        assertFalse("Rejected recreation stores no replacement bytes", data.contains(A));
        assertTrue(config.contains(MigrationArtifacts.DELETED_PREFIX + A));

        factory.failCleanup = false;
        storage.write(A, "recreated A");
        assertFalse(config.contains(MigrationArtifacts.MANIFEST));
        assertFalse(config.contains(MigrationArtifacts.DELETED_PREFIX + A));
        assertEquals("recreated A", storage.read(A));
        assertEquals("sibling B", storage.read(B));
        StorageCipher reopened = factory.forGeneration(context, KeyCipherAlgorithm.fromString(TARGET_KEY),
                StorageCipherAlgorithm.fromString(DATA), config.getString(MigrationArtifacts.ACTIVE_GENERATION, null), false);
        assertEquals("recreated A", new String(reopened.decrypt(Base64.decode(data.getString(A, null), Base64.DEFAULT)), StandardCharsets.UTF_8));
    }
}
