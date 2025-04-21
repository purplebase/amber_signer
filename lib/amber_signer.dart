import 'dart:convert';

import 'package:models/models.dart';
import 'package:signer_plugin/signer_plugin.dart';

class AmberSigner extends Signer {
  final _signerPlugin = SignerPlugin();
  bool isAvailable = false;

  AmberSigner({required super.ref});

  @override
  Future<AmberSigner> initialize() async {
    final hasExternalSigner = await _signerPlugin.isExternalSignerInstalled(
      'com.greenart7c3.nostrsigner',
    );
    if (hasExternalSigner) {
      await _signerPlugin.setPackageName('com.greenart7c3.nostrsigner');
      isAvailable = true;
    }
    return this;
  }

  @override
  Future<String?> getPublicKey() async {
    final map = await _signerPlugin.getPublicKey();
    return map['npub'] ?? map['result'];
  }

  @override
  Future<E> sign<E extends Model<E>>(
    PartialModel<E> partialEvent, {
    String? withPubkey,
  }) async {
    if (!isAvailable) {
      throw Exception("Cannot sign, missing Amber");
    }

    if (partialEvent is PartialDirectMessage) {
      final signedMessage = await _signerPlugin.nip04Encrypt(
        partialEvent.event.content,
        "",
        withPubkey!,
        (partialEvent as PartialDirectMessage).event.getFirstTagValue('p')!,
      );
      final encryptedContent = signedMessage['result'];
      partialEvent.event.content = encryptedContent;
    }

    // Remove all null fields (Amber otherwise crashes)
    final map = {
      for (final e in partialEvent.toMap().entries)
        if (e.value != null) e.key: e.value,
    };
    final signedMessage = await _signerPlugin.signEvent(
      jsonEncode(map),
      "",
      withPubkey!,
    );
    final signedEvent = jsonDecode(signedMessage['event']);
    return Model.getConstructorFor<E>()!.call(signedEvent, ref);
  }
}
