package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import android.content.SharedPreferences;
import com.it_nomads.fluttersecurestorage.FlutterSecureStorageConfig;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/** Production root loaders with a synthetic wrapping dependency. The CBC
 * fixture substitutes the equivalent host PKCS5 provider name only. */
public final class CipherRootTest {
    private static final String GENERATION = "1234567890abcdef1234567890abcdef";
    private static final class Preferences implements SharedPreferences {
        final Map<String, Object> memory = new LinkedHashMap<>(), disk = new LinkedHashMap<>();
        int commits;
        boolean fail;
        void seed(String key, String value) { memory.put(key, value); disk.put(key, value); }
        public Map<String, ?> getAll() { return new LinkedHashMap<>(memory); }
        public String getString(String key, String fallback) { return (String)memory.getOrDefault(key, fallback); }
        public boolean getBoolean(String key, boolean fallback) { return (Boolean)memory.getOrDefault(key, fallback); }
        public boolean contains(String key) { return memory.containsKey(key); }
        public Editor edit() {
            return new Editor() {
                final Map<String, Object> changes = new LinkedHashMap<>(); boolean clear;
                public Editor putString(String key, String value) { changes.put(key, value); return this; }
                public Editor putBoolean(String key, boolean value) { changes.put(key, value); return this; }
                public Editor remove(String key) { changes.put(key, null); return this; }
                public Editor clear() { clear = true; return this; }
                public boolean commit() {
                    commits++;
                    if (clear) memory.clear();
                    changes.forEach((key, value) -> { if (value == null) memory.remove(key); else memory.put(key, value); });
                    if (fail) return false;
                    disk.clear(); disk.putAll(memory); return true;
                }
                public void apply() { commit(); }
            };
        }
    }
    private static final class Stores extends Context {
        final Preferences roots = new Preferences();
        public SharedPreferences getSharedPreferences(String name, int mode) { return roots; }
    }
    private static final class Wrapper implements KeyCipher {
        int wraps, unwraps;
        public byte[] wrap(Key key) { wraps++; return key.getEncoded(); }
        public Key unwrap(byte[] value, String algorithm) {
            unwraps++;
            if (value.length != 16) throw new IllegalStateException("Synthetic wrapped root is invalid");
            return new SecretKeySpec(value, algorithm);
        }
        public Cipher getCipher(Context ignored) { return null; }
        public void deleteKey() { throw new AssertionError("Read/conversion must not delete a wrapping alias"); }
    }
    private static final class HostCbc extends StorageCipherImplementationAES18 {
        HostCbc(Context context, KeyCipher wrapper, FlutterSecureStorageConfig config) throws Exception { super(context, wrapper, null, config); }
        @Override protected Cipher getCipher() throws Exception { return Cipher.getInstance("AES/CBC/PKCS5Padding"); }
    }
    private static final FlutterSecureStorageConfig OPTIONS = new FlutterSecureStorageConfig(Map.of("storageNamespace", "syntheticRoot"));
    private static String encode(byte[] value) { return java.util.Base64.getEncoder().encodeToString(value); }
    private static void require(boolean value, String message) { if (!value) throw new AssertionError(message); }
    private interface Throwing { void run() throws Exception; }
    private static void rejected(Throwing action) throws Exception {
        try { action.run(); throw new AssertionError("Expected root refusal"); } catch (IllegalStateException expected) {}
    }

    public static void main(String[] args) throws Exception {
        Stores missing = new Stores(); Wrapper wrapper = new Wrapper();
        rejected(() -> new StorageCipherImplementationGCM(missing, wrapper, null, OPTIONS.forRootGeneration(null, false)));
        rejected(() -> new HostCbc(missing, wrapper, OPTIONS.forRootGeneration(null, false)));
        require(missing.roots.commits == 0 && wrapper.wraps == 0, "A source read cannot create a wrapped root");

        byte[] existing = new byte[16]; Arrays.fill(existing, (byte)42);
        Stores legacy = new Stores(); legacy.roots.seed(StorageCipherImplementationGCM.LEGACY_V9_KEY, encode(existing));
        StorageCipher source = new StorageCipherImplementationGCM(legacy, wrapper, null, OPTIONS.forRootGeneration(null, false));
        require(legacy.roots.commits == 0 && !legacy.roots.contains(StorageCipherImplementationGCM.WRAPPED_KEY_PREF), "Legacy-name source loading cannot rename/publish roots");
        byte[] plaintext = "synthetic round trip".getBytes(StandardCharsets.UTF_8);
        require(Arrays.equals(plaintext, source.decrypt(source.encrypt(plaintext))), "Production GCM format must round trip");

        Stores generation = new Stores();
        generation.roots.seed(StorageCipherImplementationGCM.WRAPPED_KEY_PREF, encode(existing));
        generation.roots.seed(StorageCipherImplementationAES18.WRAPPED_KEY_PREF, encode(existing));
        FlutterSecureStorageConfig targetOptions = OPTIONS.forRootGeneration(GENERATION, true);
        StorageCipher target = new StorageCipherImplementationGCM(generation, wrapper, null, targetOptions);
        require(encode(existing).equals(generation.roots.disk.get(StorageCipherImplementationGCM.WRAPPED_KEY_PREF)), "Target generation cannot overwrite canonical GCM root");
        require(generation.roots.disk.containsKey(targetOptions.rootSlot(StorageCipherImplementationGCM.WRAPPED_KEY_PREF)), "Target root must be durably isolated");
        byte[] proof = target.authenticateMigration(plaintext);
        require(!Arrays.equals(proof, source.authenticateMigration(plaintext)), "Metadata proof must belong to its actual root");
        require(!Arrays.equals(proof, target.authenticateMigration("other inventory".getBytes(StandardCharsets.UTF_8))), "Metadata proof must bind inventory bytes");
        target.deleteKey(generation);
        require(generation.roots.disk.containsKey(StorageCipherImplementationGCM.WRAPPED_KEY_PREF)
                && generation.roots.disk.containsKey(StorageCipherImplementationAES18.WRAPPED_KEY_PREF), "Exact generation retirement must preserve other slots");

        Stores cbc = new Stores(); cbc.roots.seed(StorageCipherImplementationAES18.WRAPPED_KEY_PREF, encode(existing));
        StorageCipher cbcSource = new HostCbc(cbc, wrapper, OPTIONS.forRootGeneration(null, false));
        require(Arrays.equals(plaintext, cbcSource.decrypt(cbcSource.encrypt(plaintext))) && cbc.roots.commits == 0, "CBC source remains read-only and compatible");

        Stores invalid = new Stores(); invalid.roots.seed(StorageCipherImplementationGCM.WRAPPED_KEY_PREF, encode(new byte[]{1, 2}));
        rejected(() -> new StorageCipherImplementationGCM(invalid, wrapper, null, OPTIONS.forRootGeneration(null, false)));
        require(invalid.roots.commits == 0, "An invalid existing root cannot be replaced");

        Stores failed = new Stores(); failed.roots.seed(StorageCipherImplementationGCM.WRAPPED_KEY_PREF, encode(existing)); failed.roots.fail = true;
        rejected(() -> new StorageCipherImplementationGCM(failed, wrapper, null, targetOptions));
        require(failed.roots.disk.size() == 1 && encode(existing).equals(failed.roots.disk.get(StorageCipherImplementationGCM.WRAPPED_KEY_PREF)), "Failed target commit preserves durable source root");
        System.out.println("Passed production CBC/GCM root loading, generation isolation, keyed proofs, exact cleanup and failed root commits");
    }
}
