import 'dart:convert';

import 'package:models/models.dart';
import 'package:signer_plugin/signer_plugin.dart';

const kAppId = 'com.greenart7c3.nostrsigner';
const kPubkeyStorageKey = 'amber_pubkey';

class AmberSigner extends Signer {
  SignerPlugin? _signerPlugin;

  AmberSigner(super.ref);

  @override
  Future<void> signIn({bool setAsActive = true}) async {
    _signerPlugin = SignerPlugin();
    _signerPlugin!.setPackageName(kAppId);

    if (isSignedIn) {
      // We already have a pubkey, just set as active if requested
      return super.signIn(setAsActive: setAsActive);
    }

    // No pubkey, get it from Amber
    if (!await isAvailable) {
      throw UnsupportedError('Amber is not available');
    }

    final map = await _signerPlugin!.getPublicKey();
    final npub = map['npub'] ?? map['result'];
    if (npub != null) {
      final pubkeyHex = npub.toString().decodeShareable();
      internalSetPubkey(pubkeyHex);

      // Persist the pubkey for future app restarts
      await _persistPubkey(pubkeyHex);
    }

    return super.signIn(setAsActive: setAsActive);
  }

  /// Try to restore a persisted session from previous app runs
  Future<bool> attemptAutoSignIn() async {
    try {
      final customData = await ref
          .read(storageNotifierProvider.notifier)
          .query(
            RequestFilter<CustomData>(
              tags: {
                '#d': {kPubkeyStorageKey},
              },
              limit: 1,
            ).toRequest(),
            source: const LocalSource(),
          );

      final persistedData = customData.firstOrNull;

      if (persistedData != null && persistedData.content.isNotEmpty) {
        internalSetPubkey(persistedData.content);
        await super.signIn(setAsActive: true);
        return true;
      } else {
        return false;
      }
    } catch (e) {
      return false;
    }
  }

  @override
  Future<bool> get isAvailable async {
    _signerPlugin ??= SignerPlugin();
    _signerPlugin!.setPackageName(kAppId);
    return _signerPlugin!.isExternalSignerInstalled(kAppId);
  }

  @override
  Future<List<E>> sign<E extends Model<dynamic>>(
    List<PartialModel<Model<dynamic>>> partialModels,
  ) async {
    _signerPlugin ??= SignerPlugin();
    _signerPlugin!.setPackageName(kAppId);

    if (!isSignedIn) {
      throw Exception("Cannot sign, missing Amber");
    }

    final signedModels = <E>[];

    for (final partialModel in partialModels) {
      if (partialModel is PartialDirectMessage) {
        final signedMessage = await _signerPlugin!.nip04Encrypt(
          partialModel.event.content,
          "",
          pubkey,
          partialModel.event.getFirstTagValue('p')!,
        );
        final encryptedContent = signedMessage['result'];
        partialModel.event.content = encryptedContent;
      }

      // Remove all null fields (Amber otherwise crashes)
      final map = {
        for (final e in partialModel.toMap().entries)
          if (e.value != null) e.key: e.value,
      };
      final signedMessage = await _signerPlugin!.signEvent(
        jsonEncode(map),
        "",
        pubkey,
      );
      final signedMap = jsonDecode(signedMessage['event']);
      signedModels.add(
        Model.getConstructorForKind(
              partialModel.event.kind,
            )!.call(signedMap, ref)
            as E,
      );
    }
    return signedModels;
  }

  @override
  Future<void> signOut() async {
    _signerPlugin = null;

    // Clear persisted pubkey when signing out
    await _clearPersistedPubkey();

    return super.signOut();
  }

  /// Persist pubkey to storage
  Future<void> _persistPubkey(String pubkey) async {
    try {
      final partialCustomData = PartialCustomData(
        identifier: kPubkeyStorageKey,
        content: pubkey,
      );

      final signedCustomData = await partialCustomData.signWith(this);
      await ref.read(storageNotifierProvider.notifier).save({signedCustomData});
    } catch (e) {
      // If persistence fails, continue anyway - the signer will still work
      // but won't remember the pubkey on app restart
    }
  }

  /// Clear persisted pubkey from CustomData storage
  Future<void> _clearPersistedPubkey() async {
    try {
      // Create an empty CustomData to replace the existing one
      final partialCustomData = PartialCustomData(
        identifier: kPubkeyStorageKey,
        content: '', // Empty content to clear the pubkey
      );

      final signedCustomData = partialCustomData.dummySign();
      await ref.read(storageNotifierProvider.notifier).save({signedCustomData});
    } catch (e) {
      // If clearing fails, continue anyway
    }
  }

  @override
  Future<String> nip04Decrypt(
    String encryptedMessage,
    String senderPubkey,
  ) async {
    _signerPlugin ??= SignerPlugin();
    _signerPlugin!.setPackageName(kAppId);
    final map = await _signerPlugin!.nip04Decrypt(
      encryptedMessage,
      "",
      pubkey,
      senderPubkey,
    );
    return map['result'];
  }

  @override
  Future<String> nip04Encrypt(String message, String recipientPubkey) async {
    _signerPlugin ??= SignerPlugin();
    _signerPlugin!.setPackageName(kAppId);
    final map = await _signerPlugin!.nip04Encrypt(
      message,
      "",
      pubkey,
      recipientPubkey,
    );
    return map['result'];
  }

  @override
  Future<String> nip44Decrypt(
    String encryptedMessage,
    String senderPubkey,
  ) async {
    _signerPlugin ??= SignerPlugin();
    _signerPlugin!.setPackageName(kAppId);
    final map = await _signerPlugin!.nip04Decrypt(
      encryptedMessage,
      "",
      pubkey,
      senderPubkey,
    );
    return map['result'];
  }

  @override
  Future<String> nip44Encrypt(String message, String recipientPubkey) async {
    _signerPlugin ??= SignerPlugin();
    _signerPlugin!.setPackageName(kAppId);
    final map = await _signerPlugin!.nip04Encrypt(
      message,
      "",
      pubkey,
      recipientPubkey,
    );
    return map['result'];
  }
}
