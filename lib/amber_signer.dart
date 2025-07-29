import 'dart:convert';

import 'package:models/models.dart';
import 'package:signer_plugin/signer_plugin.dart';

const kAppId = 'com.greenart7c3.nostrsigner';
const kPubkeyStorageKey = 'amber_pubkey';
const kDummySignerPrivateKey =
    '7930da683052b5a980add45c6ae310018d1a16245f246ec6408059539e7563d1';

/// A signer implementation that integrates with the Amber Nostr signer app.
///
/// This class provides a bridge between your application and the Amber signer,
/// allowing for secure signing of Nostr events, encryption/decryption of messages,
/// and session management with persistent storage.
class AmberSigner extends Signer {
  SignerPlugin? _signerPlugin;
  Bip340PrivateKeySigner? _customDataSigner;

  /// Creates a new AmberSigner instance.
  ///
  /// [ref] is the reference used for dependency injection and state management.
  AmberSigner(super.ref);

  /// Signs in to Amber and retrieves the user's public key.
  ///
  /// This method checks if Amber is available and retrieves the public key
  /// from the Amber app. The public key is then persisted to local storage
  /// for future automatic sign-ins.
  ///
  /// [setAsActive] determines whether this signer should be set as the active signer.
  /// [registerSigner] determines whether this signer should be registered in the system.
  ///
  /// Throws [UnsupportedError] if Amber is not available on the device.
  ///
  /// Example:
  /// ```dart
  /// final signer = AmberSigner(ref);
  /// await signer.signIn(); // Signs in and sets as active
  /// ```
  @override
  Future<void> signIn({setAsActive = true, registerSigner = true}) async {
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

  /// Attempts to automatically sign in using a previously persisted public key.
  ///
  /// This method looks for a stored public key from a previous session and
  /// attempts to restore the signed-in state without requiring user interaction
  /// with Amber.
  ///
  /// Returns `true` if the auto sign-in was successful, `false` otherwise.
  ///
  /// Example:
  /// ```dart
  /// final signer = AmberSigner(ref);
  /// final success = await signer.attemptAutoSignIn();
  /// if (success) {
  ///   print('Successfully restored previous session');
  /// }
  /// ```
  Future<bool> attemptAutoSignIn() async {
    try {
      final customData = await ref
          .read(storageNotifierProvider.notifier)
          .query(
            RequestFilter<CustomData>(
              authors: {Utils.derivePublicKey(kDummySignerPrivateKey)},
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

  /// Checks whether the Amber signer app is available on the device.
  ///
  /// Returns `true` if Amber is installed and can be used for signing,
  /// `false` otherwise.
  ///
  /// Example:
  /// ```dart
  /// final signer = AmberSigner(ref);
  /// if (await signer.isAvailable) {
  ///   await signer.signIn();
  /// } else {
  ///   print('Amber is not installed');
  /// }
  /// ```
  @override
  Future<bool> get isAvailable async {
    _signerPlugin ??= SignerPlugin();
    _signerPlugin!.setPackageName(kAppId);
    return _signerPlugin!.isExternalSignerInstalled(kAppId);
  }

  /// Signs a list of partial models using the Amber signer.
  ///
  /// This method takes partial models (unsigned events) and signs them using
  /// the Amber app. For direct messages, it handles NIP-04 encryption before signing.
  ///
  /// [partialModels] is the list of partial models to be signed.
  ///
  /// Returns a list of fully signed models of type [E].
  ///
  /// Throws [Exception] if the signer is not signed in.
  ///
  /// Example:
  /// ```dart
  /// final partialNote = PartialNote(content: 'Hello, Nostr!');
  /// final signedNotes = await signer.sign<Note>([partialNote]);
  /// ```
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

  /// Signs out from the Amber signer and clears any persisted session data.
  ///
  /// This method cleans up the signer plugin instance and removes any stored
  /// public key from local storage, requiring a fresh sign-in for future use.
  ///
  /// Example:
  /// ```dart
  /// await signer.signOut();
  /// print('Successfully signed out');
  /// ```
  @override
  Future<void> signOut() async {
    _signerPlugin = null;

    // Clear persisted pubkey when signing out
    await _clearPersistedPubkey();

    return super.signOut();
  }

  /// Persist pubkey to storage
  Future<void> _persistPubkey(String pubkey) async {
    await _ensureCustomDataSigner();
    final partialCustomData = PartialCustomData(
      identifier: kPubkeyStorageKey,
      content: pubkey,
    );

    final signedCustomData = await partialCustomData.signWith(
      _customDataSigner!,
    );
    await ref.read(storageNotifierProvider.notifier).save({signedCustomData});
  }

  /// Clear persisted pubkey from CustomData storage
  Future<void> _clearPersistedPubkey() async {
    await _ensureCustomDataSigner();
    // Create an empty CustomData to replace the existing one
    final partialCustomData = PartialCustomData(
      identifier: kPubkeyStorageKey,
      content: '', // Empty content to clear the pubkey
    );

    final signedCustomData = await partialCustomData.signWith(
      _customDataSigner!,
    );
    await ref.read(storageNotifierProvider.notifier).save({signedCustomData});
    signedCustomData;
  }

  Future<void> _ensureCustomDataSigner() async {
    // Use a private key signer to save the current pubkey
    // as CustomData (user preference)
    _customDataSigner = Bip340PrivateKeySigner(kDummySignerPrivateKey, ref);
    if (_customDataSigner!.isSignedIn == false) {
      // Initialize signer prevent it from registering
      // in user space as it is only used internally
      await _customDataSigner!.signIn(registerSigner: false);
    }
  }

  /// Decrypts a NIP-04 encrypted message using the Amber signer.
  ///
  /// This method decrypts messages that were encrypted using the NIP-04 standard.
  /// The decryption is performed by the Amber app using the user's private key.
  ///
  /// [encryptedMessage] is the encrypted message to decrypt.
  /// [senderPubkey] is the public key of the message sender.
  ///
  /// Returns the decrypted plaintext message.
  ///
  /// Example:
  /// ```dart
  /// final decrypted = await signer.nip04Decrypt(
  ///   encryptedMessage,
  ///   senderPubkey,
  /// );
  /// print('Decrypted: $decrypted');
  /// ```
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

  /// Encrypts a message using NIP-04 encryption via the Amber signer.
  ///
  /// This method encrypts messages using the NIP-04 standard, allowing for
  /// secure communication between Nostr users. The encryption is performed
  /// by the Amber app using the user's private key.
  ///
  /// [message] is the plaintext message to encrypt.
  /// [recipientPubkey] is the public key of the intended recipient.
  ///
  /// Returns the encrypted message that can be safely transmitted.
  ///
  /// Example:
  /// ```dart
  /// final encrypted = await signer.nip04Encrypt(
  ///   'Secret message',
  ///   recipientPubkey,
  /// );
  /// ```
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

  /// Decrypts a NIP-44 encrypted message using the Amber signer.
  ///
  /// This method decrypts messages that were encrypted using the NIP-44 standard,
  /// which provides improved security over NIP-04. The decryption is performed
  /// by the Amber app using the user's private key.
  ///
  /// [encryptedMessage] is the encrypted message to decrypt.
  /// [senderPubkey] is the public key of the message sender.
  ///
  /// Returns the decrypted plaintext message.
  ///
  /// Note: Currently uses NIP-04 implementation under the hood.
  ///
  /// Example:
  /// ```dart
  /// final decrypted = await signer.nip44Decrypt(
  ///   encryptedMessage,
  ///   senderPubkey,
  /// );
  /// ```
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

  /// Encrypts a message using NIP-44 encryption via the Amber signer.
  ///
  /// This method encrypts messages using the NIP-44 standard, which provides
  /// improved security over NIP-04. The encryption is performed by the Amber
  /// app using the user's private key.
  ///
  /// [message] is the plaintext message to encrypt.
  /// [recipientPubkey] is the public key of the intended recipient.
  ///
  /// Returns the encrypted message that can be safely transmitted.
  ///
  /// Note: Currently uses NIP-04 implementation under the hood.
  ///
  /// Example:
  /// ```dart
  /// final encrypted = await signer.nip44Encrypt(
  ///   'Secret message',
  ///   recipientPubkey,
  /// );
  /// ```
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
