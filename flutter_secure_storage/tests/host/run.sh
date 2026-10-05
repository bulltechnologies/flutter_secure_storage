#!/bin/sh
set -eu
# Supply an already-installed org.json jar; never downloads dependencies.
json_jar=${1:?Usage: sh tests/host/run.sh /absolute/path/to/org.json.jar [output_directory]}
test_output=${2:-${TMPDIR:-/tmp}/index_owned_fss_host_tests}
host_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
native_sources="$host_dir/../../android/src/main/java"
mkdir -p "$test_output"
javac -cp "$json_jar" -d "$test_output" \
  "$host_dir"/src/android/content/*.java \
  "$host_dir"/src/android/util/*.java \
  "$host_dir"/src/androidx/annotation/*.java \
  "$host_dir/src/OrdinaryMigrationTest.java" \
  "$host_dir/src/com/it_nomads/fluttersecurestorage/ciphers/CipherRootTest.java" \
  "$native_sources/com/it_nomads/fluttersecurestorage/CheckedPreferences.java" \
  "$native_sources/com/it_nomads/fluttersecurestorage/MigrationArtifacts.java" \
  "$native_sources/com/it_nomads/fluttersecurestorage/OrdinaryMigration.java" \
  "$native_sources/com/it_nomads/fluttersecurestorage/NamespacedConfigSource.java" \
  "$native_sources/com/it_nomads/fluttersecurestorage/MigrationBackup.java" \
  "$native_sources/com/it_nomads/fluttersecurestorage/FlutterSecureStorageConfig.java" \
  "$native_sources/com/it_nomads/fluttersecurestorage/ciphers/StorageCipher.java" \
  "$native_sources/com/it_nomads/fluttersecurestorage/ciphers/KeyCipher.java" \
  "$native_sources/com/it_nomads/fluttersecurestorage/ciphers/MigrationAuthentication.java" \
  "$native_sources/com/it_nomads/fluttersecurestorage/ciphers/StorageCipherImplementationGCM.java" \
  "$native_sources/com/it_nomads/fluttersecurestorage/ciphers/StorageCipherImplementationAES18.java"
java -cp "$test_output:$json_jar" OrdinaryMigrationTest
java -cp "$test_output:$json_jar" com.it_nomads.fluttersecurestorage.ciphers.CipherRootTest
