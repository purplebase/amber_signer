# amber_signer

Amber signer for [models](https://github.com/purplebase/models).

## Usage

The constructor needs a `ref`, so you can initialize it in a custom initialization provider, for example.

```dart

AmberSigner? amberSigner; // or: late final AmberSigner amberSigner;

final customInitializationProvider = FutureProvider((ref) async {
  await ref.read(initializationProvider(StorageConfiguration(...)).future);
  amberSigner = AmberSigner(ref);
});
```

Then just sign partial events:

```dart
final note = await PartialNote('hello world').signWith(amberSigner!);

// If Amber manages multiple keys, specify which:
await PartialNote('test').signWith(amberSigner!, withPubkey: pubkey);
```

## License

MIT