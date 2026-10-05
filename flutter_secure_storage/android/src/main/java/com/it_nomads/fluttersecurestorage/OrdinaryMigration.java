package com.it_nomads.fluttersecurestorage;

import android.content.SharedPreferences;
import android.util.Base64;
import com.it_nomads.fluttersecurestorage.ciphers.StorageCipher;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.json.JSONArray;
import org.json.JSONObject;

/** Ordinary cipher conversion only. Authentication/profile selection remains
 * with the host. Every dependency boundary is durable before dependent effects. */
public final class OrdinaryMigration {
    public interface Ciphers {
        StorageCipher load(String keyAlgorithm, String dataAlgorithm, String generation,
                          boolean mayCreate) throws Exception;
        void retire(String keyAlgorithm, String dataAlgorithm, String generation) throws Exception;
    }

    private final SharedPreferences data;
    private final NamespacedConfigSource config;
    private final Ciphers ciphers;
    private final String prefix;
    private final String sourceKeyAlgorithm, sourceDataAlgorithm;
    private final String targetKeyAlgorithm, targetDataAlgorithm;

    public OrdinaryMigration(SharedPreferences data, NamespacedConfigSource config,
            Ciphers ciphers, String prefix, String sourceKeyAlgorithm, String sourceDataAlgorithm,
            String targetKeyAlgorithm, String targetDataAlgorithm) {
        this.data = data;
        this.config = config;
        this.ciphers = ciphers;
        this.prefix = prefix + "_";
        this.sourceKeyAlgorithm = sourceKeyAlgorithm;
        this.sourceDataAlgorithm = sourceDataAlgorithm;
        this.targetKeyAlgorithm = targetKeyAlgorithm;
        this.targetDataAlgorithm = targetDataAlgorithm;
    }

    /** A cached writer must not acknowledge recreation while a pending exact
     * intent can erase it on reopen. Never discard the intent to permit a write. */
    public StorageCipher beforeWrite(String canonicalKey) throws Exception {
        config.commit(config.edit());
        String intent = config.getString(MigrationArtifacts.DELETED_PREFIX + canonicalKey, null);
        String raw = config.getString(MigrationArtifacts.MANIFEST, null);
        if (intent == null || raw == null) return null;
        Manifest manifest = Manifest.parse(raw, prefix, config.getFamilyName());
        if (!manifest.generation.equals(intent)) return null;
        if (!canonicalKey.startsWith(prefix) || !"published".equals(manifest.phase)) {
            throw new IllegalStateException("Retired record cannot be recreated before publication");
        }
        StorageCipher target = run();
        if (manifest.generation.equals(config.getString(MigrationArtifacts.DELETED_PREFIX + canonicalKey, null))) {
            throw new IllegalStateException("Retired record cleanup is not durably complete");
        }
        // Cleanup can return target after a failed journal commit that removed
        // the intent in RAM only. Certify its retirement before accepting bytes.
        config.commit(config.edit());
        // The run certified target authority and the exact data erase, then
        // retired this finite intent only after successful source cleanup.
        return target;
    }

    /** Caller and exact deletion share MigrationArtifacts.familyLock. */
    public StorageCipher run() throws Exception {
        rejectOpaqueSource();
        String raw = config.getString(MigrationArtifacts.MANIFEST, null);
        Manifest manifest = raw == null ? prepare() : Manifest.parse(raw, prefix, config.getFamilyName());
        verifyArtifactOwnership(manifest);
        if (!manifest.targetKey.equals(targetKeyAlgorithm)
                || !manifest.targetData.equals(targetDataAlgorithm)) {
            throw new IllegalStateException("Pending migration has a different target policy");
        }
        String active = config.getString(MigrationArtifacts.ACTIVE_GENERATION, null);
        if ("published".equals(manifest.phase)) {
            if (!manifest.generation.equals(active)) throw new IllegalStateException("Unpublished target authority");
            StorageCipher target = ciphers.load(manifest.targetKey, manifest.targetData, manifest.generation, false);
            verifyProof(target, manifest.identity("target"), manifest.targetProof);
            verifyPublishedTarget(manifest, target);
            // A failed commit can leave published authority visible in RAM.
            // Certify that authority before retiring any recoverable source.
            config.commit(config.edit());
            finishPublishedDeletions(manifest);
            cleanup(manifest);
            return target;
        }
        if (!equal(active, manifest.sourceGeneration)) {
            throw new IllegalStateException("Source authority changed during migration");
        }
        StorageCipher source = manifest.records.isEmpty() ? null
                : ciphers.load(manifest.sourceKey, manifest.sourceData, manifest.sourceGeneration, false);
        if (source != null) verifyProof(source, manifest.identity("source"), manifest.sourceProof);
        Map<String, byte[]> plaintext = sourceInventory(manifest, source);
        // Retrying a failed prepared/ready commit must first make the complete
        // journal durable. Otherwise a stop after the next copy commit could
        // create orphan artifacts with no published inventory on disk.
        config.commit(config.edit());
        // All snapshots form one checked transition; an interruption in prepared
        // phase is repaired from identical still-canonical source bytes only.
        SharedPreferences.Editor snapshots = data.edit();
        for (Record record : manifest.records) {
            if (!deleted(manifest, record.key)) {
                String copy = MigrationArtifacts.sourceCopyKey(manifest.generation, record.key);
                if (!data.contains(copy)) snapshots.putString(copy, data.getString(record.key, null));
            }
        }
        CheckedPreferences.commit(data, snapshots);
        verifySnapshotInventory(manifest);

        StorageCipher target = ciphers.load(manifest.targetKey, manifest.targetData,
                manifest.generation, "prepared".equals(manifest.phase));
        if ("prepared".equals(manifest.phase)) {
            manifest.targetProof = encode(target.authenticateMigration(manifest.identity("target")));
            manifest.phase = "ready";
            persist(manifest, false);
        } else {
            verifyProof(target, manifest.identity("target"), manifest.targetProof);
        }
        // Successor roots are durable and authenticated before any canonical
        // ciphertext replacement. The complete source remains separately usable.
        SharedPreferences.Editor replacement = data.edit();
        for (Record record : manifest.records) {
            if (deleted(manifest, record.key)) replacement.remove(record.key);
        }
        for (Map.Entry<String, byte[]> entry : plaintext.entrySet()) {
            replacement.putString(entry.getKey(), encode(target.encrypt(entry.getValue())));
        }
        CheckedPreferences.commit(data, replacement);
        for (Record record : manifest.records) {
            if (deleted(manifest, record.key)) continue;
            byte[] decoded = decrypt(target, data.getString(record.key, null));
            if (!record.plainVerifier.equals(plainVerifier(source, manifest, record.key, decoded))) {
                throw new IllegalStateException("Target verification failed");
            }
        }
        manifest.phase = "published";
        persist(manifest, true);
        cleanup(manifest);
        return target;
    }

    private Manifest prepare() throws Exception {
        // Old generic progress flags do not establish a complete source or root
        // generation. Preserve them for an explicit conservative recovery path.
        if (config.contains("FlutterSecureStorageBackupStatus")) {
            throw new IllegalStateException("Legacy migration state requires preserved recovery");
        }
        for (String key : data.getAll().keySet()) {
            if (key.startsWith(MigrationArtifacts.SOURCE_PREFIX)) {
                throw new IllegalStateException("Source copies have no authenticated migration authority");
            }
        }
        for (String key : config.getAll().keySet()) {
            if (key.startsWith(prefix) && key.endsWith("_MIGRATED")) {
                throw new IllegalStateException("Legacy migration progress is ambiguous");
            }
        }
        List<String> keys = canonicalKeys();
        for (String key : keys) {
            if (key.endsWith("_BACKUP")) throw new IllegalStateException("Legacy source inventory is ambiguous");
        }
        Manifest manifest = new Manifest();
        manifest.family = config.getFamilyName();
        manifest.generation = UUID.randomUUID().toString().replace("-", "");
        manifest.sourceGeneration = config.getString(MigrationArtifacts.ACTIVE_GENERATION, null);
        manifest.sourceKey = sourceKeyAlgorithm;
        manifest.sourceData = sourceDataAlgorithm;
        manifest.targetKey = targetKeyAlgorithm;
        manifest.targetData = targetDataAlgorithm;
        manifest.phase = "prepared";
        StorageCipher source = keys.isEmpty() ? null
                : ciphers.load(sourceKeyAlgorithm, sourceDataAlgorithm, manifest.sourceGeneration, false);
        for (String key : keys) {
            String ciphertext = data.getString(key, null);
            manifest.records.add(new Record(key, digest(ciphertext.getBytes(StandardCharsets.UTF_8)),
                    plainVerifier(source, manifest, key, decrypt(source, ciphertext))));
        }
        if (source != null) manifest.sourceProof = encode(source.authenticateMigration(manifest.identity("source")));
        persist(manifest, false);
        return manifest;
    }

    private void verifyArtifactOwnership(Manifest manifest) {
        for (String physical : data.getAll().keySet()) {
            if (!physical.startsWith(MigrationArtifacts.SOURCE_PREFIX)) continue;
            String canonical = MigrationArtifacts.canonicalKeyFromSourceCopy(physical);
            if (canonical == null || !manifest.hasKey(canonical)
                    || !physical.equals(MigrationArtifacts.sourceCopyKey(manifest.generation, canonical))) {
                throw new IllegalStateException("Unrecognized migration source ownership");
            }
        }
    }

    private Map<String, byte[]> sourceInventory(Manifest manifest, StorageCipher source) throws Exception {
        Map<String, byte[]> plaintext = new LinkedHashMap<>();
        for (Record record : manifest.records) {
            if (deleted(manifest, record.key)) continue;
            String copy = MigrationArtifacts.sourceCopyKey(manifest.generation, record.key);
            String raw = data.getString(copy, null);
            if (raw == null && "prepared".equals(manifest.phase)) raw = data.getString(record.key, null);
            if (raw == null || !record.cipherDigest.equals(digest(raw.getBytes(StandardCharsets.UTF_8)))) {
                throw new IllegalStateException("Incomplete or contradictory source inventory");
            }
            byte[] decoded = decrypt(source, raw);
            if (!record.plainVerifier.equals(plainVerifier(source, manifest, record.key, decoded))) throw new IllegalStateException("Source verification failed");
            plaintext.put(record.key, decoded);
        }
        if ("prepared".equals(manifest.phase)) {
            for (String key : canonicalKeys()) {
                if (!manifest.hasKey(key)) throw new IllegalStateException("Source inventory changed");
            }
        }
        return plaintext;
    }

    private void verifySnapshotInventory(Manifest manifest) throws Exception {
        for (Record record : manifest.records) {
            if (deleted(manifest, record.key)) continue;
            String raw = data.getString(MigrationArtifacts.sourceCopyKey(manifest.generation, record.key), null);
            if (raw == null || !record.cipherDigest.equals(digest(raw.getBytes(StandardCharsets.UTF_8)))) {
                throw new IllegalStateException("Source snapshot persistence was not verified");
            }
        }
    }

    private void verifyPublishedTarget(Manifest manifest, StorageCipher target) throws Exception {
        for (Record record : manifest.records) {
            if (!deleted(manifest, record.key) && !data.contains(record.key)) {
                throw new IllegalStateException("Published target inventory is incomplete");
            }
        }
        // Published targets may have legitimate later writes. Verify all current
        // records under the authenticated successor root, without rolling back.
        for (String key : canonicalKeys()) {
            if (!deleted(manifest, key)) decrypt(target, data.getString(key, null));
        }
    }

    private void finishPublishedDeletions(Manifest manifest) {
        SharedPreferences.Editor erase = data.edit();
        boolean hasIntent = false;
        for (Map.Entry<String, ?> entry : config.getAll().entrySet()) {
            if (entry.getKey().startsWith(MigrationArtifacts.DELETED_PREFIX)
                    && manifest.generation.equals(entry.getValue())) {
                String canonical = entry.getKey().substring(MigrationArtifacts.DELETED_PREFIX.length());
                if (!canonical.startsWith(prefix)) continue;
                erase.remove(canonical);
                hasIntent = true;
            }
        }
        // Force persistence even if a failed prior erase made these keys look
        // absent in RAM. Cleanup must not retire an unfulfilled durable intent.
        if (hasIntent) CheckedPreferences.commit(data, erase);
    }

    private void persist(Manifest manifest, boolean publish) throws Exception {
        SharedPreferences.Editor editor = config.edit().putString(MigrationArtifacts.MANIFEST, manifest.json());
        if (publish) {
            editor.putString(MigrationArtifacts.ACTIVE_GENERATION, manifest.generation)
                    .putString("FlutterSecureSAlgorithmKey", manifest.targetKey)
                    .putString("FlutterSecureSAlgorithmStorage", manifest.targetData);
        }
        config.commit(editor);
    }

    private void cleanup(Manifest manifest) {
        try {
            SharedPreferences.Editor copies = data.edit();
            for (Record record : manifest.records) {
                copies.remove(MigrationArtifacts.sourceCopyKey(manifest.generation, record.key));
            }
            CheckedPreferences.commit(data, copies);
            ciphers.retire(manifest.sourceKey, manifest.sourceData, manifest.sourceGeneration);
            SharedPreferences.Editor journal = config.edit().remove(MigrationArtifacts.MANIFEST);
            for (Map.Entry<String, ?> entry : config.getAll().entrySet()) {
                if (entry.getKey().startsWith(MigrationArtifacts.DELETED_PREFIX)
                        && entry.getKey().substring(MigrationArtifacts.DELETED_PREFIX.length()).startsWith(prefix)
                        && manifest.generation.equals(entry.getValue())) journal.remove(entry.getKey());
            }
            config.commit(journal);
        } catch (Exception failure) {
            // Publication and complete target verification already succeeded.
            // Retain generation authority and retry only cleanup on next open.
        }
    }

    private boolean deleted(Manifest manifest, String key) {
        return manifest.generation.equals(config.getString(MigrationArtifacts.DELETED_PREFIX + key, null));
    }

    private List<String> canonicalKeys() {
        List<String> result = new ArrayList<>();
        for (Map.Entry<String, ?> entry : data.getAll().entrySet()) {
            String key = entry.getKey();
            if (key.startsWith(prefix)) {
                if (!(entry.getValue() instanceof String)) throw new IllegalStateException("Unsupported source record");
                result.add(key);
            } else if (!key.startsWith(MigrationArtifacts.SOURCE_PREFIX) && key.contains(prefix)) {
                throw new IllegalStateException("Unknown encrypted source identity");
            }
        }
        Collections.sort(result);
        return result;
    }

    private void rejectOpaqueSource() {
        if (data.contains("__androidx_security_crypto_encrypted_prefs_key_keyset__")
                || data.contains("__androidx_security_crypto_encrypted_prefs_value_keyset__")) {
            throw new IllegalStateException("Encrypted source identifiers are unavailable");
        }
    }

    private static boolean equal(Object a, Object b) { return a == null ? b == null : a.equals(b); }
    private static byte[] decrypt(StorageCipher cipher, String raw) throws Exception {
        if (cipher == null || raw == null) throw new IllegalStateException("Missing encrypted source record");
        return cipher.decrypt(Base64.decode(raw, Base64.DEFAULT));
    }
    private static String encode(byte[] value) { return Base64.encodeToString(value, Base64.NO_WRAP); }
    private static String digest(byte[] value) throws Exception { return encode(MessageDigest.getInstance("SHA-256").digest(value)); }
    private static String plainVerifier(StorageCipher source, Manifest manifest, String key, byte[] plaintext) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bytes);
        for (String field : new String[]{"index.fss.migration.record.v1", manifest.family, manifest.generation, key}) out.writeUTF(field);
        out.writeInt(plaintext.length);
        out.write(plaintext);
        // Plaintext hashes would expose low-entropy values to a preference-file
        // dictionary attack. Only the established source root can verify this.
        return encode(source.authenticateMigration(bytes.toByteArray()));
    }
    private static void verifyProof(StorageCipher cipher, byte[] identity, String proof) throws Exception {
        if (proof == null || !MessageDigest.isEqual(cipher.authenticateMigration(identity), Base64.decode(proof, Base64.DEFAULT))) {
            throw new IllegalStateException("Migration generation authentication failed");
        }
    }

    private static final class Record {
        final String key, cipherDigest, plainVerifier;
        Record(String key, String cipherDigest, String plainVerifier) {
            this.key = key; this.cipherDigest = cipherDigest; this.plainVerifier = plainVerifier;
        }
    }
    private static final class Manifest {
        String family, generation, sourceGeneration, sourceKey, sourceData, targetKey, targetData, phase;
        String sourceProof, targetProof;
        final List<Record> records = new ArrayList<>();
        boolean hasKey(String key) { for (Record record : records) if (record.key.equals(key)) return true; return false; }
        byte[] identity(String role) throws Exception {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bytes);
            for (String field : new String[]{"index.fss.migration.v1", role, family, generation,
                    sourceGeneration == null ? "" : sourceGeneration, sourceKey, sourceData, targetKey, targetData}) out.writeUTF(field);
            out.writeInt(records.size());
            for (Record record : records) { out.writeUTF(record.key); out.writeUTF(record.cipherDigest); out.writeUTF(record.plainVerifier); }
            return bytes.toByteArray();
        }
        String json() throws Exception {
            JSONObject value = new JSONObject().put("version", 1).put("family", family).put("generation", generation)
                    .put("sourceGeneration", sourceGeneration == null ? JSONObject.NULL : sourceGeneration)
                    .put("sourceKey", sourceKey).put("sourceData", sourceData).put("targetKey", targetKey)
                    .put("targetData", targetData).put("phase", phase)
                    .put("sourceProof", sourceProof == null ? JSONObject.NULL : sourceProof)
                    .put("targetProof", targetProof == null ? JSONObject.NULL : targetProof);
            JSONArray inventory = new JSONArray();
            for (Record record : records) inventory.put(new JSONObject().put("key", record.key)
                    .put("cipherDigest", record.cipherDigest).put("plainVerifier", record.plainVerifier));
            return value.put("inventory", inventory).toString();
        }
        static Manifest parse(String raw, String prefix, String expectedFamily) throws Exception {
            JSONObject value = new JSONObject(raw);
            Manifest result = new Manifest();
            if (value.getInt("version") != 1) throw new IllegalStateException("Unsupported migration version");
            result.family = value.getString("family");
            if (!result.family.equals(expectedFamily)) throw new IllegalStateException("Migration belongs to a different data family");
            result.generation = value.getString("generation");
            result.sourceGeneration = value.isNull("sourceGeneration") ? null : value.getString("sourceGeneration");
            if (!MigrationArtifacts.isGeneration(result.generation)
                    || (result.sourceGeneration != null && !MigrationArtifacts.isGeneration(result.sourceGeneration))
                    || result.generation.equals(result.sourceGeneration)) throw new IllegalStateException("Invalid generation identity");
            result.sourceKey = value.getString("sourceKey"); result.sourceData = value.getString("sourceData");
            result.targetKey = value.getString("targetKey"); result.targetData = value.getString("targetData");
            result.phase = value.getString("phase");
            if (!result.phase.equals("prepared") && !result.phase.equals("ready") && !result.phase.equals("published")) {
                throw new IllegalStateException("Unsupported migration phase");
            }
            result.sourceProof = value.isNull("sourceProof") ? null : value.getString("sourceProof");
            result.targetProof = value.isNull("targetProof") ? null : value.getString("targetProof");
            JSONArray inventory = value.getJSONArray("inventory");
            String previous = "";
            for (int i = 0; i < inventory.length(); i++) {
                JSONObject record = inventory.getJSONObject(i);
                String key = record.getString("key");
                if (!key.startsWith(prefix) || key.compareTo(previous) <= 0) throw new IllegalStateException("Invalid source inventory");
                result.records.add(new Record(key, record.getString("cipherDigest"), record.getString("plainVerifier")));
                previous = key;
            }
            return result;
        }
    }
}
