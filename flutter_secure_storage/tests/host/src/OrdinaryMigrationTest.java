import android.content.Context;
import android.content.SharedPreferences;
import com.it_nomads.fluttersecurestorage.CheckedPreferences;
import com.it_nomads.fluttersecurestorage.FlutterSecureStorageConfig;
import com.it_nomads.fluttersecurestorage.MigrationArtifacts;
import com.it_nomads.fluttersecurestorage.MigrationBackup;
import com.it_nomads.fluttersecurestorage.NamespacedConfigSource;
import com.it_nomads.fluttersecurestorage.OrdinaryMigration;
import com.it_nomads.fluttersecurestorage.ciphers.StorageCipher;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.json.JSONObject;

/** Compiles the production coordinator with synthetic Android preferences.
 * Cryptography uses random synthetic AES roots; no OS/device secrets or stores. */
public final class OrdinaryMigrationTest {
    private static final String PREFIX = "syntheticPrefix";
    private static final String A = PREFIX + "_rootA", B = PREFIX + "_rootB";
    private static final String KEY = "RSA_ECB_OAEPwithSHA_256andMGF1Padding";
    private static final String CBC = "AES_CBC_PKCS7Padding", GCM = "AES_GCM_NoPadding";
    private static final class Stop extends Error {}
    private static final class Counter {
        int count, fail = -1, before = -1, after = -1;
        String phase;
        void reset() { count = 0; fail = before = after = -1; phase = null; }
    }
    private static final class Preferences implements SharedPreferences {
        final Counter counter;
        Map<String, Object> memory = new LinkedHashMap<>(), disk = new LinkedHashMap<>();
        Preferences(Counter counter) { this.counter = counter; }
        void seed(String key, Object value) { memory.put(key, value); disk.put(key, value); }
        void restart() { memory = new LinkedHashMap<>(disk); }
        public Map<String, ?> getAll() { return new LinkedHashMap<>(memory); }
        public String getString(String key, String fallback) { Object value = memory.get(key); return value == null ? fallback : (String)value; }
        public boolean getBoolean(String key, boolean fallback) { Object value = memory.get(key); return value == null ? fallback : (Boolean)value; }
        public boolean contains(String key) { return memory.containsKey(key); }
        public Editor edit() {
            return new Editor() {
                Map<String, Object> changes = new LinkedHashMap<>();
                boolean clear;
                public Editor putString(String key, String value) { changes.put(key, value); return this; }
                public Editor putBoolean(String key, boolean value) { changes.put(key, value); return this; }
                public Editor remove(String key) { changes.put(key, null); return this; }
                public Editor clear() { clear = true; return this; }
                public boolean commit() {
                    if (clear) memory.clear();
                    changes.forEach((key, value) -> { if (value == null) memory.remove(key); else memory.put(key, value); });
                    counter.count++;
                    if (counter.before == counter.count) throw new Stop();
                    if (counter.fail == counter.count) return false;
                    disk = new LinkedHashMap<>(memory);
                    if (counter.after == counter.count) throw new Stop();
                    Object manifest = changes.get(MigrationArtifacts.MANIFEST);
                    if (counter.phase != null && manifest instanceof String
                            && ((String)manifest).contains("\"phase\":\"" + counter.phase + "\"")) throw new Stop();
                    return true;
                }
                public void apply() { commit(); }
            };
        }
    }
    private static final class Stores extends Context {
        final Counter counter = new Counter();
        final Map<String, Preferences> families = new LinkedHashMap<>();
        public Preferences getSharedPreferences(String name, int mode) { return families.computeIfAbsent(name, unused -> new Preferences(counter)); }
        void restart() { families.values().forEach(Preferences::restart); counter.reset(); }
    }
    private static final class AesCipher implements StorageCipher {
        final byte[] root;
        final String dataAlgorithm;
        AesCipher(byte[] root, String dataAlgorithm) { this.root = root; this.dataAlgorithm = dataAlgorithm; }
        public byte[] encrypt(byte[] plaintext) throws Exception {
            boolean gcm = dataAlgorithm.equals(GCM);
            byte[] iv = new byte[gcm ? 12 : 16]; new SecureRandom().nextBytes(iv);
            Cipher cipher = Cipher.getInstance(gcm ? "AES/GCM/NoPadding" : "AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(root, "AES"),
                    gcm ? new GCMParameterSpec(128, iv) : new IvParameterSpec(iv));
            byte[] payload = cipher.doFinal(plaintext), result = new byte[iv.length + payload.length];
            System.arraycopy(iv, 0, result, 0, iv.length); System.arraycopy(payload, 0, result, iv.length, payload.length);
            return result;
        }
        public byte[] decrypt(byte[] ciphertext) throws Exception {
            boolean gcm = dataAlgorithm.equals(GCM); int length = gcm ? 12 : 16;
            Cipher cipher = Cipher.getInstance(gcm ? "AES/GCM/NoPadding" : "AES/CBC/PKCS5Padding");
            byte[] iv = java.util.Arrays.copyOfRange(ciphertext, 0, length);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(root, "AES"),
                    gcm ? new GCMParameterSpec(128, iv) : new IvParameterSpec(iv));
            return cipher.doFinal(java.util.Arrays.copyOfRange(ciphertext, length, ciphertext.length));
        }
        public void deleteKey(Context ignored) { throw new AssertionError("Generic cipher deletion must not retire source"); }
        public byte[] authenticateMigration(byte[] payload) throws Exception {
            Mac mac = Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(root, "HmacSHA256")); return mac.doFinal(payload);
        }
    }
    private static final class Fixture implements OrdinaryMigration.Ciphers {
        final Stores stores = new Stores();
        final Preferences data = stores.getSharedPreferences("data", 0);
        final Preferences roots = stores.getSharedPreferences("roots", 0);
        final Preferences configPrefs = stores.getSharedPreferences("FlutterSecureStorageConfiguration:data", 0);
        final NamespacedConfigSource config = new NamespacedConfigSource(stores, "data");
        int sourceCreationRequests;
        boolean failRetirement;
        Fixture() throws Exception {
            byte[] key = new byte[16]; new SecureRandom().nextBytes(key);
            roots.seed("canonical", encode(key));
            StorageCipher source = new AesCipher(key, CBC);
            data.seed(A, encode(source.encrypt(bytes("original A"))));
            data.seed(B, encode(source.encrypt(bytes("original B"))));
            configPrefs.seed("FlutterSecureSAlgorithmKey", KEY);
            configPrefs.seed("FlutterSecureSAlgorithmStorage", CBC);
        }
        public StorageCipher load(String keyAlgorithm, String dataAlgorithm, String generation, boolean mayCreate) throws Exception {
            String slot = generation == null ? "canonical" : generation;
            String raw = roots.getString(slot, null);
            if (generation == null && mayCreate) sourceCreationRequests++;
            if (raw == null) {
                if (!mayCreate) throw new IllegalStateException("Source/target root missing");
                byte[] key = new byte[16]; new SecureRandom().nextBytes(key); raw = encode(key);
                CheckedPreferences.commit(roots, roots.edit().putString(slot, raw));
            }
            if (mayCreate) CheckedPreferences.commit(roots, roots.edit());
            return new AesCipher(decode(raw), dataAlgorithm);
        }
        public void retire(String key, String data, String generation) {
            if (failRetirement) throw new IllegalStateException("Injected cleanup failure");
            CheckedPreferences.commit(roots, roots.edit().remove(generation == null ? "canonical" : generation));
        }
        OrdinaryMigration migration() { return new OrdinaryMigration(data, config, this, PREFIX, KEY, CBC, KEY, GCM); }
        StorageCipher admit() throws Exception {
            if (config.contains(MigrationArtifacts.MANIFEST) || !GCM.equals(config.getString("FlutterSecureSAlgorithmStorage", null))) return migration().run();
            return load(KEY, GCM, config.getString(MigrationArtifacts.ACTIVE_GENERATION, null), false);
        }
        void originalsReadable() throws Exception {
            StorageCipher target = admit();
            require("original A".equals(text(target.decrypt(decode(data.getString(A, null))))), "A must survive restart");
            require("original B".equals(text(target.decrypt(decode(data.getString(B, null))))), "B must survive restart");
            require(sourceCreationRequests == 0, "Recovery cannot create source roots");
        }
    }
    private static byte[] bytes(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    private static String text(byte[] value) { return new String(value, StandardCharsets.UTF_8); }
    private static String encode(byte[] value) { return java.util.Base64.getEncoder().encodeToString(value); }
    private static byte[] decode(String value) { return java.util.Base64.getDecoder().decode(value); }
    private static void require(boolean value, String message) { if (!value) throw new AssertionError(message); }
    private static void expectPreservedFailure(Throwing action) throws Exception {
        try { action.run(); throw new AssertionError("Expected preserved refusal"); } catch (IllegalStateException expected) {}
    }
    private interface Throwing { void run() throws Exception; }

    private static void everyPersistenceBoundary() throws Exception {
        Fixture baseline = new Fixture(); baseline.migration().run(); int boundaries = baseline.stores.counter.count;
        int cases = 0;
        for (int cut = 1; cut <= boundaries; cut++) {
            for (int kind = 0; kind < 3; kind++) {
                Fixture fixture = new Fixture();
                if (kind == 0) fixture.stores.counter.fail = cut;
                if (kind == 1) fixture.stores.counter.before = cut;
                if (kind == 2) fixture.stores.counter.after = cut;
                try { fixture.migration().run(); } catch (Exception | Stop injected) {}
                fixture.stores.restart(); fixture.originalsReadable(); cases++;
            }
            Fixture twice = new Fixture(); twice.stores.counter.after = cut;
            try { twice.migration().run(); } catch (Exception | Stop injected) {}
            twice.stores.restart(); twice.stores.counter.after = 4;
            try { twice.admit(); } catch (Exception | Stop injected) {}
            twice.stores.restart(); twice.originalsReadable(); cases++;
            Fixture inProcess = new Fixture(); inProcess.stores.counter.fail = cut;
            try { inProcess.migration().run(); } catch (Exception injected) {}
            inProcess.stores.counter.fail = -1;
            inProcess.originalsReadable();
            inProcess.stores.restart(); inProcess.originalsReadable(); cases++;
            Fixture retryCut = new Fixture(); retryCut.stores.counter.fail = cut;
            try { retryCut.migration().run(); } catch (Exception injected) {}
            retryCut.stores.counter.fail = -1;
            retryCut.stores.counter.after = retryCut.stores.counter.count + 1;
            try { retryCut.admit(); } catch (Stop injected) {}
            retryCut.stores.restart(); retryCut.originalsReadable(); cases++;
        }
        System.out.println("Passed " + cases + " failed-commit/interruption/repeated-recovery cases across " + boundaries + " boundaries");
    }

    private static void missingOrCorruptSourceHasNoMutation() throws Exception {
        Fixture missing = new Fixture(); missing.roots.memory.clear(); missing.roots.disk.clear();
        Map<String, Object> old = new LinkedHashMap<>(missing.data.disk);
        expectPreservedFailure(() -> missing.migration().run());
        require(old.equals(missing.data.disk) && missing.stores.counter.count == 0, "Missing source must be preserved without writes");
        Fixture corrupt = new Fixture(); corrupt.data.seed(B, encode(bytes("not a valid old ciphertext")));
        old = new LinkedHashMap<>(corrupt.data.disk);
        try { corrupt.migration().run(); throw new AssertionError("Corruption must reject"); } catch (javax.crypto.BadPaddingException | javax.crypto.IllegalBlockSizeException expected) {}
        require(old.equals(corrupt.data.disk) && corrupt.stores.counter.count == 0, "One unreadable source cannot become partial success");
    }

    private static void deletionDuringRecoveryDoesNotResurrect() throws Exception {
        Fixture fixture = new Fixture(); fixture.stores.counter.phase = "ready";
        try { fixture.migration().run(); } catch (Stop expected) {}
        fixture.stores.restart();
        MigrationArtifacts.recordKeyDeletion(fixture.configPrefs, A);
        SharedPreferences.Editor erase = fixture.data.edit().remove(A);
        for (String key : fixture.data.getAll().keySet()) if (MigrationArtifacts.isSourceCopyKeyFor(key, A)) erase.remove(key);
        CheckedPreferences.commit(fixture.data, erase);
        fixture.stores.restart(); StorageCipher target = fixture.admit();
        require(!fixture.data.contains(A), "Deleted logical key cannot return from source copies");
        require("original B".equals(text(target.decrypt(decode(fixture.data.getString(B, null))))), "Sibling key must survive exact deletion");
        require(!fixture.configPrefs.contains(MigrationArtifacts.DELETED_PREFIX + A), "Suppression retires with its generation");
        CheckedPreferences.commit(fixture.data, fixture.data.edit().putString(A, encode(target.encrypt(bytes("authorized new A")))));
        fixture.stores.restart(); target = fixture.admit();
        require("authorized new A".equals(text(target.decrypt(decode(fixture.data.getString(A, null))))), "Later recreation must be permitted");
    }

    private static void durableDeletionFinishesAfterEraseFailure() throws Exception {
        Fixture fixture = new Fixture(); fixture.stores.counter.phase = "ready";
        try { fixture.admit(); } catch (Stop expected) {}
        fixture.stores.restart();
        MigrationArtifacts.recordKeyDeletion(fixture.configPrefs, A);
        SharedPreferences.Editor erase = fixture.data.edit().remove(A);
        for (String key : fixture.data.getAll().keySet()) if (MigrationArtifacts.isSourceCopyKeyFor(key, A)) erase.remove(key);
        fixture.stores.counter.fail = fixture.stores.counter.count + 1;
        expectPreservedFailure(() -> CheckedPreferences.commit(fixture.data, erase));
        fixture.stores.restart();
        StorageCipher target = fixture.admit();
        require(!fixture.data.contains(A), "Durable exact deletion intent must finish erasure before target publication");
        require("original B".equals(text(target.decrypt(decode(fixture.data.getString(B, null))))), "Interrupted exact erase cannot damage siblings");
        fixture.stores.restart(); target = fixture.admit();
        require(!fixture.data.contains(A) && "original B".equals(text(target.decrypt(decode(fixture.data.getString(B, null))))), "Completed erasure must survive restart");

        Fixture published = new Fixture(); published.failRetirement = true;
        published.admit();
        MigrationArtifacts.recordKeyDeletion(published.configPrefs, A);
        published.stores.counter.fail = published.stores.counter.count + 1;
        expectPreservedFailure(() -> CheckedPreferences.commit(published.data, published.data.edit().remove(A)));
        published.stores.restart(); published.failRetirement = false; target = published.admit();
        require(!published.data.contains(A), "Published cleanup cannot clear an unfulfilled exact deletion intent");
        require("original B".equals(text(target.decrypt(decode(published.data.getString(B, null))))), "Published erase recovery preserves siblings");

        Fixture laterKey = new Fixture(); laterKey.failRetirement = true; target = laterKey.admit();
        String newKey = PREFIX + "_newRevision";
        CheckedPreferences.commit(laterKey.data, laterKey.data.edit().putString(newKey, encode(target.encrypt(bytes("new revision")))));
        MigrationArtifacts.recordKeyDeletion(laterKey.configPrefs, newKey);
        String otherGenerationMarker = MigrationArtifacts.DELETED_PREFIX + PREFIX + "_unrelatedGeneration";
        String otherPrefixMarker = MigrationArtifacts.DELETED_PREFIX + "otherPrefix_otherFamily";
        laterKey.configPrefs.seed(otherGenerationMarker, "1234567890abcdef1234567890abcdef");
        laterKey.configPrefs.seed(otherPrefixMarker, laterKey.configPrefs.getString(MigrationArtifacts.ACTIVE_GENERATION, null));
        laterKey.stores.counter.fail = laterKey.stores.counter.count + 1;
        expectPreservedFailure(() -> CheckedPreferences.commit(laterKey.data, laterKey.data.edit().remove(newKey)));
        laterKey.stores.restart(); laterKey.failRetirement = false; target = laterKey.admit();
        require(!laterKey.data.contains(newKey), "Cleanup must finish an exact deletion of a later published-generation record");
        require("original B".equals(text(target.decrypt(decode(laterKey.data.getString(B, null))))), "Later-record deletion cannot expand to sibling records");
        require(laterKey.configPrefs.contains(otherGenerationMarker) && laterKey.configPrefs.contains(otherPrefixMarker), "Exact cleanup must retain unrelated deletion identities");
    }

    private static Fixture pendingDeletion(boolean published) throws Exception {
        Fixture fixture = new Fixture();
        if (published) {
            fixture.failRetirement = true; fixture.admit(); fixture.failRetirement = false;
        } else {
            fixture.stores.counter.phase = "ready";
            try { fixture.admit(); } catch (Stop expected) {}
        }
        fixture.stores.restart();
        MigrationArtifacts.recordKeyDeletion(fixture.configPrefs, A);
        fixture.stores.counter.reset();
        return fixture;
    }

    private static void everyDeletionRecoveryBoundary() throws Exception {
        int cases = 0;
        for (boolean published : new boolean[]{false, true}) {
            Fixture baseline = pendingDeletion(published); baseline.admit();
            int boundaries = baseline.stores.counter.count;
            for (int cut = 1; cut <= boundaries; cut++) {
                for (int kind = 0; kind < 3; kind++) {
                    Fixture fixture = pendingDeletion(published);
                    if (kind == 0) fixture.stores.counter.fail = cut;
                    if (kind == 1) fixture.stores.counter.before = cut;
                    if (kind == 2) fixture.stores.counter.after = cut;
                    try { fixture.admit(); } catch (Exception | Stop injected) {}
                    fixture.stores.restart();
                    StorageCipher target = fixture.admit();
                    require(!fixture.data.contains(A), "A durable deletion cannot return after a recovery cut");
                    require("original B".equals(text(target.decrypt(decode(fixture.data.getString(B, null))))), "Deletion recovery cut must preserve sibling data");
                    cases++;
                }
            }
        }
        System.out.println("Passed " + cases + " ready/published deletion-recovery persistence cuts");
    }

    private static void authenticatedIdentityAndPublishedCleanup() throws Exception {
        Fixture fixture = new Fixture(); fixture.stores.counter.phase = "ready";
        try { fixture.migration().run(); } catch (Stop expected) {}
        fixture.stores.restart();
        JSONObject manifest = new JSONObject(fixture.configPrefs.getString(MigrationArtifacts.MANIFEST, null));
        manifest.getJSONArray("inventory").remove(0);
        fixture.configPrefs.seed(MigrationArtifacts.MANIFEST, manifest.toString());
        Map<String, Object> preserved = new LinkedHashMap<>(fixture.data.disk);
        expectPreservedFailure(() -> fixture.admit()); require(preserved.equals(fixture.data.disk), "Tampered inventory must not mutate data");

        Fixture cleanup = new Fixture(); cleanup.failRetirement = true;
        StorageCipher target = cleanup.admit();
        require(cleanup.config.contains(MigrationArtifacts.MANIFEST), "Cleanup failure retains published authority");
        CheckedPreferences.commit(cleanup.data, cleanup.data.edit().putString(A, encode(target.encrypt(bytes("later legitimate A")))));
        cleanup.stores.restart(); cleanup.failRetirement = false; target = cleanup.admit();
        require("later legitimate A".equals(text(target.decrypt(decode(cleanup.data.getString(A, null))))), "Cleanup recovery must not roll back later target writes");
        require(!cleanup.config.contains(MigrationArtifacts.MANIFEST), "Completed cleanup retires recovery journal");
    }

    private static void orphanAndUnknownArtifactsHaveNoMutation() throws Exception {
        Fixture orphan = new Fixture();
        orphan.data.seed(MigrationArtifacts.sourceCopyKey("1234567890abcdef1234567890abcdef", A), orphan.data.getString(A, null));
        Map<String, Object> preserved = new LinkedHashMap<>(orphan.data.disk);
        expectPreservedFailure(() -> orphan.admit());
        require(preserved.equals(orphan.data.disk) && orphan.stores.counter.count == 0, "Orphan copies cannot be treated as an empty/fresh source");

        Fixture unknown = new Fixture(); unknown.stores.counter.phase = "ready";
        try { unknown.admit(); } catch (Stop expected) {}
        unknown.stores.restart();
        unknown.data.seed(MigrationArtifacts.sourceCopyKey("1234567890abcdef1234567890abcdef", A), unknown.data.getString(A, null));
        preserved = new LinkedHashMap<>(unknown.data.disk);
        expectPreservedFailure(() -> unknown.admit());
        require(preserved.equals(unknown.data.disk) && unknown.stores.counter.count == 0, "An unrelated generation cannot acquire current manifest ownership");
    }

    private static void copiedFamilyCannotReplayAuthority() throws Exception {
        Fixture fixture = new Fixture(); fixture.stores.counter.phase = "ready";
        try { fixture.admit(); } catch (Stop expected) {}
        fixture.stores.restart();
        // Model the strongest replay precondition: both families can load the
        // same global source/target wrapping roots and copied ciphertext bytes.
        NamespacedConfigSource sibling = new NamespacedConfigSource(fixture.stores, "sibling");
        Preferences siblingPrefs = fixture.stores.getSharedPreferences("FlutterSecureStorageConfiguration:sibling", 0);
        fixture.configPrefs.disk.forEach((key, value) -> siblingPrefs.seed(key, value));
        Map<String, Object> preserved = new LinkedHashMap<>(fixture.data.disk);
        OrdinaryMigration replay = new OrdinaryMigration(fixture.data, sibling, fixture, PREFIX, KEY, CBC, KEY, GCM);
        expectPreservedFailure(replay::run);
        require(preserved.equals(fixture.data.disk) && fixture.stores.counter.count == 0, "Copied-family authority must be refused before mutations");
        JSONObject manifest = new JSONObject(siblingPrefs.getString(MigrationArtifacts.MANIFEST, null));
        manifest.put("family", "sibling");
        siblingPrefs.seed(MigrationArtifacts.MANIFEST, manifest.toString());
        expectPreservedFailure(replay::run);
        require(preserved.equals(fixture.data.disk) && fixture.stores.counter.count == 0, "Renaming the copied family cannot forge its keyed identity");
        fixture.originalsReadable();
    }

    private static void plaintextVerificationDoesNotPublishDictionaryHashes() throws Exception {
        Fixture fixture = new Fixture();
        StorageCipher source = fixture.load(KEY, CBC, null, false);
        fixture.data.seed(B, encode(source.encrypt(bytes("original A"))));
        fixture.stores.counter.phase = "ready";
        try { fixture.admit(); } catch (Stop expected) {}
        fixture.stores.restart();
        JSONObject manifest = new JSONObject(fixture.configPrefs.getString(MigrationArtifacts.MANIFEST, null));
        String verifierA = manifest.getJSONArray("inventory").getJSONObject(0).getString("plainVerifier");
        String verifierB = manifest.getJSONArray("inventory").getJSONObject(1).getString("plainVerifier");
        require(!verifierA.equals(encode(MessageDigest.getInstance("SHA-256").digest(bytes("original A")))), "Verifier cannot expose an unkeyed plaintext dictionary oracle");
        require(!verifierA.equals(verifierB), "Equal plaintext under one root must still bind exact logical record identity");
        StorageCipher target = fixture.admit();
        require("original A".equals(text(target.decrypt(decode(fixture.data.getString(A, null)))))
                && "original A".equals(text(target.decrypt(decode(fixture.data.getString(B, null))))), "Keyed verifiers must preserve valid plaintext equality through conversion");
    }

    private static void cachedRecreationMustSurviveRestart() throws Exception {
        Fixture fixture = new Fixture(); fixture.failRetirement = true;
        StorageCipher cached = fixture.admit();
        MigrationArtifacts.recordKeyDeletion(fixture.configPrefs, A);
        SharedPreferences.Editor erase = fixture.data.edit().remove(A);
        for (String physical : fixture.data.getAll().keySet()) if (MigrationArtifacts.isSourceCopyKeyFor(physical, A)) erase.remove(physical);
        CheckedPreferences.commit(fixture.data, erase);
        // A matching intent must be resolved even when initialize returns its
        // cached target. Unfinished source cleanup is a refusal, never a write.
        expectPreservedFailure(() -> fixture.migration().beforeWrite(A));
        require(!fixture.data.contains(A), "Rejected recreation must not store new bytes");
        fixture.failRetirement = false;
        StorageCipher recovered = fixture.migration().beforeWrite(A);
        if (recovered != null) cached = recovered;
        CheckedPreferences.commit(fixture.data, fixture.data.edit().putString(A, encode(cached.encrypt(bytes("acknowledged new A")))));
        require("acknowledged new A".equals(text(cached.decrypt(decode(fixture.data.getString(A, null))))), "Fixture must establish acknowledged target bytes before restart");
        fixture.stores.restart(); fixture.failRetirement = false;
        StorageCipher reopened = fixture.admit();
        require(fixture.data.contains(A) && "acknowledged new A".equals(text(reopened.decrypt(decode(fixture.data.getString(A, null))))), "Cached same-key recreation must not be erased by pending finite suppression");
    }

    private static void everyRecreationRecoveryBoundary() throws Exception {
        int cases = 0;
        Fixture baseline = pendingDeletion(true); baseline.migration().beforeWrite(A);
        int boundaries = baseline.stores.counter.count;
        for (int cut = 1; cut <= boundaries; cut++) {
            for (int kind = 0; kind < 3; kind++) {
                Fixture fixture = pendingDeletion(true);
                if (kind == 0) fixture.stores.counter.fail = cut;
                if (kind == 1) fixture.stores.counter.before = cut;
                if (kind == 2) fixture.stores.counter.after = cut;
                try { fixture.migration().beforeWrite(A); } catch (Exception | Stop injected) {}
                fixture.stores.restart();
                StorageCipher target = fixture.migration().beforeWrite(A);
                if (target == null) target = fixture.admit();
                CheckedPreferences.commit(fixture.data, fixture.data.edit().putString(A, encode(target.encrypt(bytes("durable recreated A")))));
                fixture.stores.restart(); target = fixture.admit();
                require("durable recreated A".equals(text(target.decrypt(decode(fixture.data.getString(A, null))))), "Acknowledged recreation must survive every preflight persistence cut");
                require("original B".equals(text(target.decrypt(decode(fixture.data.getString(B, null))))), "Recreation preflight cannot alter siblings");
                cases++;
            }
            Fixture sameProcess = pendingDeletion(true); sameProcess.stores.counter.fail = cut;
            try { sameProcess.migration().beforeWrite(A); } catch (Exception injected) {}
            sameProcess.stores.counter.fail = -1;
            StorageCipher target = sameProcess.migration().beforeWrite(A);
            if (target == null) target = sameProcess.admit();
            CheckedPreferences.commit(sameProcess.data, sameProcess.data.edit().putString(A, encode(target.encrypt(bytes("durable recreated A")))));
            sameProcess.stores.restart(); target = sameProcess.admit();
            require("durable recreated A".equals(text(target.decrypt(decode(sameProcess.data.getString(A, null))))), "Same-process retry must certify RAM-only retired intent before recreation");
            require("original B".equals(text(target.decrypt(decode(sameProcess.data.getString(B, null))))), "Same-process retry cannot damage sibling records");
            cases++;
        }
        for (String phase : new String[]{"prepared", "ready"}) {
            Fixture uncommitted = new Fixture(); uncommitted.stores.counter.phase = phase;
            try { uncommitted.admit(); } catch (Stop expected) {}
            uncommitted.stores.restart(); MigrationArtifacts.recordKeyDeletion(uncommitted.configPrefs, A);
            Map<String, Object> preserved = new LinkedHashMap<>(uncommitted.data.disk);
            expectPreservedFailure(() -> uncommitted.migration().beforeWrite(A));
            require(preserved.equals(uncommitted.data.disk), "Unpublished recreation cannot mutate source records");
        }
        System.out.println("Passed " + cases + " recreation preflight persistence cuts and unpublished refusal");
    }

    private static void grammarAndLegacyFailure() throws Exception {
        String generation = "1234567890abcdef1234567890abcdef";
        String copy = MigrationArtifacts.sourceCopyKey(generation, A);
        require(A.equals(MigrationArtifacts.canonicalKeyFromSourceCopy(copy)), "Parser must recover exact canonical identity");
        require(!MigrationArtifacts.isSourceCopyKeyFor(copy, B), "Exact deletion cannot expand to siblings");
        require(MigrationArtifacts.canonicalKeyFromSourceCopy(MigrationArtifacts.SOURCE_PREFIX + "bad__" + A) == null, "Malformed generation cannot grant ownership");
        require(MigrationArtifacts.isGenerationAliasFor("app.FlutterSecureStoragePluginKeyOAEP.scope" + MigrationArtifacts.GENERATION_SUFFIX + generation, "app", "scope"), "Own generation alias matches");
        require(!MigrationArtifacts.isGenerationAliasFor("app.FlutterSecureStoragePluginKeyOAEP.other" + MigrationArtifacts.GENERATION_SUFFIX + generation, "app", "scope"), "Sibling family alias must survive");
        FlutterSecureStorageConfig options = new FlutterSecureStorageConfig(Map.of("storageNamespace", "scope", "resetOnError", "false", "migrateWithBackup", "true"));
        require(options.forRootGeneration(generation, false).rootSlot("root").equals("root" + MigrationArtifacts.GENERATION_SUFFIX + generation), "Generation slot remains within root family");
        require(!options.forRootGeneration(null, false).mayCreateKeys(), "Read-only source capability is explicit");
        Object lock = MigrationArtifacts.familyLock("synthetic epoch family");
        long epoch = MigrationArtifacts.familyEpoch("synthetic epoch family");
        require(MigrationArtifacts.invalidateFamily("synthetic epoch family") == epoch + 1, "Full erasure must invalidate old cached capability");
        require(MigrationArtifacts.familyLock("synthetic epoch family") == lock, "Cache invalidation cannot replace shared serialization lock");
        Fixture legacy = new Fixture(); legacy.configPrefs.seed("FlutterSecureStorageBackupStatus", "started");
        legacy.data.seed(A + "_BACKUP", legacy.data.getString(A, null));
        Map<String, Object> old = new LinkedHashMap<>(legacy.data.disk);
        expectPreservedFailure(() -> MigrationBackup.createBackup(legacy.data, legacy.roots, legacy.config, options, PREFIX));
        require(old.equals(legacy.data.disk), "Incomplete backup must never be discarded");
        Fixture failure = new Fixture(); failure.stores.counter.fail = 1;
        expectPreservedFailure(() -> MigrationBackup.setBackupStatus(failure.config, options, "complete"));
        require(!failure.configPrefs.disk.containsKey("FlutterSecureStorageBackupStatus"), "Failed COMPLETE write cannot authorize effects");
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && args[0].equals("cached-recreation")) {
            cachedRecreationMustSurviveRestart();
            return;
        }
        everyPersistenceBoundary();
        missingOrCorruptSourceHasNoMutation();
        deletionDuringRecoveryDoesNotResurrect();
        durableDeletionFinishesAfterEraseFailure();
        everyDeletionRecoveryBoundary();
        authenticatedIdentityAndPublishedCleanup();
        orphanAndUnknownArtifactsHaveNoMutation();
        copiedFamilyCannotReplayAuthority();
        plaintextVerificationDoesNotPublishDictionaryHashes();
        cachedRecreationMustSurviveRestart();
        everyRecreationRecoveryBoundary();
        grammarAndLegacyFailure();
        System.out.println("Passed: complete source preservation, read-only refusal, authenticated generations, finite exact deletion, cleanup recovery");
    }
}
