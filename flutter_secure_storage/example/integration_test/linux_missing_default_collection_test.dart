import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

/// Linux integration tests for an initialized Secret Service with no default
/// collection.
///
/// This is the normal state of a fresh desktop profile before its first secret
/// is stored. Reads and deletes must treat it as an empty store rather than a
/// locked keyring. An interactive first write may open the desktop's
/// collection-creation prompt and succeed. The headless CI environment makes
/// that prompt unavailable and verifies that the write fails safely instead.
/// CI runs the suite both with no collections and with an unrelated secret in
/// another collection to verify that only matching data blocks access.
///
/// Run with a keyring daemon registered on D-Bus but no default alias:
///   flutter test integration_test/linux_missing_default_collection_test.dart -d linux

const _storage = FlutterSecureStorage();

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  group(
    'Missing default collection',
    () {
      testWidgets('read returns null', (_) async {
        expect(await _storage.read(key: 'k'), isNull);
      });

      testWidgets('readAll returns an empty map', (_) async {
        expect(await _storage.readAll(), isEmpty);
      });

      testWidgets('containsKey returns false', (_) async {
        expect(await _storage.containsKey(key: 'k'), isFalse);
      });

      testWidgets(
        'write reports a platform error when collection creation cannot prompt',
        (_) async {
          await expectLater(
            _storage.write(key: 'k', value: 'v'),
            throwsA(
              isA<PlatformException>().having(
                (error) => error.code,
                'code',
                isNot('KeyringLocked'),
              ),
            ),
          );
        },
      );

      testWidgets('delete is a successful no-op', (_) async {
        await expectLater(_storage.delete(key: 'k'), completes);
      });

      testWidgets('deleteAll is a successful no-op', (_) async {
        await expectLater(_storage.deleteAll(), completes);
      });
    },
    skip: kIsWeb || !Platform.isLinux ? 'Linux only' : null,
  );
}
