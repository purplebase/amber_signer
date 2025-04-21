import 'dart:convert';

import 'package:models/models.dart';
import 'package:signer_plugin/signer_plugin.dart';

class AmberSigner extends Signer {
  final _signerPlugin = SignerPlugin();
  bool isAvailable = false;

  AmberSigner(super.ref);

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
    PartialModel<E> partialModel, {
    String? withPubkey,
  }) async {
    if (!isAvailable) {
      throw Exception("Cannot sign, missing Amber");
    }

    final pubkey = withPubkey ?? await getPublicKey();

    if (partialModel is PartialDirectMessage) {
      final signedMessage = await _signerPlugin.nip04Encrypt(
        partialModel.event.content,
        "",
        withPubkey!,
        (partialModel as PartialDirectMessage).event.getFirstTagValue('p')!,
      );
      final encryptedContent = signedMessage['result'];
      partialModel.event.content = encryptedContent;
    }

    // Remove all null fields (Amber otherwise crashes)
    final map = {
      for (final e in partialModel.toMap().entries)
        if (e.value != null) e.key: e.value,
    };
    final signedMessage = await _signerPlugin.signEvent(
      jsonEncode(map),
      "",
      pubkey!,
    );
    final signedMap = jsonDecode(signedMessage['event']);
    return Model.getConstructorFor<E>()!.call(signedMap, ref);
  }
}
