import 'dart:convert';

import 'package:models/models.dart';
import 'package:signer_plugin/signer_plugin.dart';

class AmberSigner extends Signer {
  SignerPlugin? _signerPlugin;

  AmberSigner(super.ref);

  @override
  Future<void> initialize({bool active = true}) async {
    _signerPlugin = SignerPlugin();
    if (!await isAvailable) {
      throw UnsupportedError('Amber is not available');
    }

    final map = await _signerPlugin!.getPublicKey();
    final npub = map['npub'] ?? map['result'];
    if (npub != null) {
      internalSetPubkey(npub.toString().decodeShareable());
    }

    return super.initialize(active: active);
  }

  @override
  Future<bool> get isAvailable {
    return _signerPlugin!.isExternalSignerInstalled(
      'com.greenart7c3.nostrsigner',
    );
  }

  @override
  Future<List<E>> sign<E extends Model<dynamic>>(
    List<PartialModel<Model<dynamic>>> partialModels,
  ) async {
    if (!isInitialized) {
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
      signedModels.add(Model.getConstructorFor<E>()!.call(signedMap, ref));
    }
    return signedModels;
  }

  @override
  Future<void> dispose() {
    _signerPlugin = null;
    return super.dispose();
  }

  @override
  Future<String> nip04Decrypt(
    String encryptedMessage,
    String senderPubkey,
  ) async {
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
    final map = await _signerPlugin!.nip04Encrypt(
      message,
      "",
      pubkey,
      recipientPubkey,
    );
    return map['result'];
  }
}
