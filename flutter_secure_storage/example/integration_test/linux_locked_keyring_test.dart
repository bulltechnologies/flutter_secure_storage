import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

/// Linux integration tests for an existing, genuinely locked default
/// collection.
///
/// CI creates and uses the default collection, locks it over D-Bus, and then
/// runs this file with graphical prompting disabled.

const _storage = FlutterSecureStorage();

Future<void> _expectLockedKeyring(Future<void> Function() operation) async {
  Object? caught;
  try {
    await operation();
  } on Object catch (error) {
    caught = error;
  }

  expect(caught, isNotNull, reason: 'Expected an exception');
  expect(caught, isNot(isA<FormatException>()));
  expect(caught, isA<PlatformException>());

  final error = caught! as PlatformException;
  expect(error.code, 'KeyringLocked');
  expect(error.message, 'KeyringLocked');
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  group(
    'Locked keyring',
    () {
      testWidgets('read throws KeyringLocked', (_) async {
        await _expectLockedKeyring(
          () async {
            await _storage.read(key: 'k');
          },
        );
      });

      testWidgets('write throws KeyringLocked', (_) async {
        await _expectLockedKeyring(
          () => _storage.write(key: 'k', value: 'v'),
        );
      });

      testWidgets('readAll throws KeyringLocked', (_) async {
        await _expectLockedKeyring(_storage.readAll);
      });

      testWidgets('containsKey throws KeyringLocked', (_) async {
        await _expectLockedKeyring(
          () async {
            await _storage.containsKey(key: 'k');
          },
        );
      });

      testWidgets('delete throws KeyringLocked', (_) async {
        await _expectLockedKeyring(() => _storage.delete(key: 'k'));
      });

      testWidgets('deleteAll throws KeyringLocked', (_) async {
        await _expectLockedKeyring(_storage.deleteAll);
      });
    },
    skip: kIsWeb || !Platform.isLinux ? 'Linux only' : null,
  );
}
