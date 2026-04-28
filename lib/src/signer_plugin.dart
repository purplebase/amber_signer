import 'package:flutter/services.dart';

/// Information about a signer app installed on the device.
class SignerAppInfo {
  final String name;
  final String packageName;
  final String iconData;
  final String? iconUrl;

  SignerAppInfo({
    required this.name,
    required this.packageName,
    required this.iconData,
    this.iconUrl,
  });

  factory SignerAppInfo.fromMap(Map<String, dynamic> map) {
    return SignerAppInfo(
      name: map['name'] as String,
      packageName: map['packageName'] as String,
      iconData: map['iconData'] as String? ?? '',
      iconUrl: map['iconUrl'] as String?,
    );
  }
}

/// Thin Dart client over the vendored amber_signer Android plugin.
///
/// This is the in-package replacement for the third-party `signer_plugin` Dart
/// API. The native side lives at
/// `android/src/main/java/dev/purplebase/amber_signer/AmberSignerPlugin.java` and
/// guarantees one-shot replies and cancellable activity results — see
/// [cancelPending].
class SignerPlugin {
  static const _channel = MethodChannel('amber_signer');

  Future<bool> isExternalSignerInstalled(String packageName) async {
    final isInstalled = await _channel.invokeMethod<bool>(
      'isExternalSignerInstalled',
      {'packageName': packageName},
    );
    return isInstalled ?? false;
  }

  Future<List<SignerAppInfo>> getInstalledSignerApps() async {
    final apps = await _channel.invokeMethod<List<dynamic>>(
      'getInstalledSignerApps',
    );
    return (apps ?? const [])
        .map((e) => SignerAppInfo.fromMap(Map<String, dynamic>.from(e as Map)))
        .toList();
  }

  Future<void> setPackageName(String packageName) async {
    await _channel.invokeMethod<void>('setPackageName', {
      'packageName': packageName,
    });
  }

  Future<Map<String, dynamic>> getPublicKey({String? permissions}) async {
    final result = await _channel.invokeMethod<Map<dynamic, dynamic>>(
      'getPublicKey',
      {'permissions': permissions},
    );
    return Map<String, dynamic>.from(result ?? const {});
  }

  Future<Map<String, dynamic>> signEvent(
    String eventJson,
    String eventId,
    String npub,
  ) async {
    final result = await _channel.invokeMethod<Map<dynamic, dynamic>>(
      'signEvent',
      {'eventJson': eventJson, 'eventId': eventId, 'npub': npub},
    );
    return Map<String, dynamic>.from(result ?? const {});
  }

  Future<Map<String, dynamic>> nip04Encrypt(
    String plainText,
    String id,
    String npub,
    String pubKey,
  ) async {
    final result = await _channel.invokeMethod<Map<dynamic, dynamic>>(
      'nip04Encrypt',
      {'plainText': plainText, 'id': id, 'npub': npub, 'pubKey': pubKey},
    );
    return Map<String, dynamic>.from(result ?? const {});
  }

  Future<Map<String, dynamic>> nip04Decrypt(
    String encryptedText,
    String id,
    String npub,
    String pubKey,
  ) async {
    final result = await _channel.invokeMethod<Map<dynamic, dynamic>>(
      'nip04Decrypt',
      {
        'encryptedText': encryptedText,
        'id': id,
        'npub': npub,
        'pubKey': pubKey,
      },
    );
    return Map<String, dynamic>.from(result ?? const {});
  }

  Future<Map<String, dynamic>> nip44Encrypt(
    String plainText,
    String id,
    String npub,
    String pubKey,
  ) async {
    final result = await _channel.invokeMethod<Map<dynamic, dynamic>>(
      'nip44Encrypt',
      {'plainText': plainText, 'id': id, 'npub': npub, 'pubKey': pubKey},
    );
    return Map<String, dynamic>.from(result ?? const {});
  }

  Future<Map<String, dynamic>> nip44Decrypt(
    String encryptedText,
    String id,
    String npub,
    String pubKey,
  ) async {
    final result = await _channel.invokeMethod<Map<dynamic, dynamic>>(
      'nip44Decrypt',
      {
        'encryptedText': encryptedText,
        'id': id,
        'npub': npub,
        'pubKey': pubKey,
      },
    );
    return Map<String, dynamic>.from(result ?? const {});
  }

  Future<Map<String, dynamic>> decryptZapEvent(
    String eventJson,
    String id,
    String npub,
  ) async {
    final result = await _channel.invokeMethod<Map<dynamic, dynamic>>(
      'decryptZapEvent',
      {'eventJson': eventJson, 'id': id, 'npub': npub},
    );
    return Map<String, dynamic>.from(result ?? const {});
  }

  Future<Map<String, dynamic>> getRelays(String id, String npub) async {
    final result = await _channel.invokeMethod<Map<dynamic, dynamic>>(
      'getRelays',
      {'id': id, 'current_user': npub},
    );
    return Map<String, dynamic>.from(result ?? const {});
  }

  /// Cancels every in-flight signer request. Each pending Dart awaiter will
  /// complete with a [PlatformException] whose code is `CANCELLED`.
  ///
  /// Use this when the host activity is about to enter a state where stale
  /// signer replies would be unsafe (e.g. before launching the system package
  /// installer, on logout, or when navigating away from a flow that issued a
  /// signer request).
  Future<void> cancelPending() async {
    await _channel.invokeMethod<void>('cancelPending');
  }
}
