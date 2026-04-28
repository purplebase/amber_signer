package dev.purplebase.amber_signer;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ResolveInfo;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import androidx.activity.result.ActivityResult;
import androidx.annotation.NonNull;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import io.flutter.embedding.engine.plugins.FlutterPlugin;
import io.flutter.embedding.engine.plugins.activity.ActivityAware;
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding;
import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.MethodChannel.MethodCallHandler;
import io.flutter.plugin.common.MethodChannel.Result;

import biz.nostr.android.nip55.AppInfo;
import biz.nostr.android.nip55.IntentBuilder;
import biz.nostr.android.nip55.Signer;

/**
 * AmberSignerPlugin — vendored, fixed fork of biz.nostr.signer_plugin.
 *
 * <p>Behavioral fixes vs upstream:
 * <ul>
 *   <li>Every {@link Result} returned to Flutter is wrapped in {@link SafeResult}, which
 *       enforces at-most-once reply. This eliminates the
 *       {@code java.lang.IllegalStateException: Reply already submitted} crash that
 *       killed the host activity when an activity result was delivered twice or after
 *       a stale reply.
 *   <li>Every in-flight signer call can be cancelled via the {@code cancelPending} method
 *       channel call, or implicitly when the activity is detached or reattached after a
 *       configuration change. Cancellation replies once with a {@code CANCELLED} error so
 *       Dart awaiters get a deterministic exception instead of hanging forever.
 *   <li>The {@code onMethodCall} switch no longer falls through {@code nip44Decrypt} into
 *       {@code decryptZapEvent} (upstream missing {@code break}).
 *   <li>The {@link ActivityResultHandler} no longer mixes
 *       {@code androidx.activity.result.ActivityResultLauncher} (which uses requestCode
 *       {@code -1}) with the legacy {@code onActivityResult} path; only the legacy path
 *       is used, with unique 16-bit request codes per launch.
 * </ul>
 */
public class AmberSignerPlugin implements FlutterPlugin, MethodCallHandler, ActivityAware {

    private static final String TAG = "AmberSignerPlugin";
    private static final String CHANNEL_NAME = "amber_signer";

    private MethodChannel channel;
    private ActivityResultHandler activityResultHandler;
    private String signerPackageName;
    private Context context;
    private Activity activity;

    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    /** Tracks every in-flight reply so we can cancel them on lifecycle events. */
    private final List<SafeResult> pendingReplies = new ArrayList<>();

    // ───── FlutterPlugin ──────────────────────────────────────────────────────

    @Override
    public void onAttachedToEngine(@NonNull FlutterPluginBinding binding) {
        Log.d(TAG, "onAttachedToEngine");
        this.context = binding.getApplicationContext();
        channel = new MethodChannel(binding.getBinaryMessenger(), CHANNEL_NAME);
        channel.setMethodCallHandler(this);
    }

    @Override
    public void onDetachedFromEngine(@NonNull FlutterPluginBinding binding) {
        Log.d(TAG, "onDetachedFromEngine");
        cancelAllPending("Engine detached");
        if (channel != null) {
            channel.setMethodCallHandler(null);
            channel = null;
        }
        context = null;
    }

    // ───── ActivityAware ──────────────────────────────────────────────────────

    @Override
    public void onAttachedToActivity(@NonNull ActivityPluginBinding binding) {
        Log.d(TAG, "onAttachedToActivity");
        this.activity = binding.getActivity();
        this.activityResultHandler = new DefaultActivityResultHandler();
        this.activityResultHandler.init(activity, binding);
    }

    @Override
    public void onDetachedFromActivity() {
        Log.d(TAG, "onDetachedFromActivity");
        // Flush any in-flight signer calls so Dart awaiters get a CANCELLED error
        // instead of a stale Result that would later cause "Reply already submitted".
        cancelAllPending("Activity detached");
        if (activityResultHandler != null) {
            activityResultHandler.dispose();
            activityResultHandler = null;
        }
        this.activity = null;
    }

    @Override
    public void onReattachedToActivityForConfigChanges(@NonNull ActivityPluginBinding binding) {
        Log.d(TAG, "onReattachedToActivityForConfigChanges");
        // We treat config changes the same as detach+attach: any pending result is cancelled,
        // forcing Dart to re-issue the call against the recreated activity.
        onAttachedToActivity(binding);
    }

    @Override
    public void onDetachedFromActivityForConfigChanges() {
        Log.d(TAG, "onDetachedFromActivityForConfigChanges");
        onDetachedFromActivity();
    }

    // ───── MethodCallHandler ─────────────────────────────────────────────────

    @Override
    public void onMethodCall(@NonNull MethodCall call, @NonNull Result rawResult) {
        SafeResult result = trackReply(rawResult);
        try {
            switch (call.method) {
                case "isExternalSignerInstalled":
                    isExternalSignerInstalled(call, result);
                    break;
                case "getInstalledSignerApps":
                    getInstalledSignerApps(call, result);
                    break;
                case "setPackageName":
                    setPackageName(call, result);
                    break;
                case "getPublicKey":
                    getPublicKey(call, result);
                    break;
                case "signEvent":
                    signEvent(call, result);
                    break;
                case "nip04Encrypt":
                    nip04Encrypt(call, result);
                    break;
                case "nip04Decrypt":
                    nip04Decrypt(call, result);
                    break;
                case "nip44Encrypt":
                    nip44Encrypt(call, result);
                    break;
                case "nip44Decrypt":
                    nip44Decrypt(call, result);
                    break;
                case "decryptZapEvent":
                    decryptZapEvent(call, result);
                    break;
                case "getRelays":
                    getRelays(call, result);
                    break;
                case "cancelPending":
                    cancelAllPending("Cancelled by Flutter");
                    result.success(null);
                    break;
                default:
                    result.notImplemented();
            }
        } catch (Throwable t) {
            Log.e(TAG, "Unhandled exception in " + call.method, t);
            result.error("EXCEPTION", t.getMessage(), null);
        }
    }

    // ───── Reply tracking & cancellation ─────────────────────────────────────

    private SafeResult trackReply(Result raw) {
        SafeResult sr = new SafeResult(raw, mainHandler) {
            @Override
            void onFinished() {
                synchronized (pendingReplies) {
                    pendingReplies.remove(this);
                }
            }
        };
        synchronized (pendingReplies) {
            pendingReplies.add(sr);
        }
        return sr;
    }

    private void cancelAllPending(@NonNull String reason) {
        List<SafeResult> snapshot;
        synchronized (pendingReplies) {
            if (pendingReplies.isEmpty()) {
                if (activityResultHandler != null) activityResultHandler.cancelAll();
                return;
            }
            snapshot = new ArrayList<>(pendingReplies);
            pendingReplies.clear();
        }
        // Cancel any pending activity launches first; their callbacks will fail their
        // SafeResult through the normal handleActivityResult path, but trySetClosed()
        // ensures we never double-reply.
        if (activityResultHandler != null) {
            activityResultHandler.cancelAll();
        }
        for (SafeResult sr : snapshot) {
            sr.error("CANCELLED", reason, null);
        }
    }

    // ───── Method implementations ────────────────────────────────────────────

    private void isExternalSignerInstalled(MethodCall call, SafeResult result) {
        String packageName = call.argument("packageName");
        List<ResolveInfo> signers = Signer.isExternalSignerInstalled(context, packageName);
        result.success(!signers.isEmpty());
    }

    private void getInstalledSignerApps(MethodCall call, SafeResult result) {
        List<AppInfo> signerAppInfos = Signer.getInstalledSignerApps(context);
        List<Object> appsList = new ArrayList<>();
        for (AppInfo info : signerAppInfos) {
            Map<String, Object> appInfo = new HashMap<>();
            appInfo.put("name", info.name);
            appInfo.put("packageName", info.packageName);
            appInfo.put("iconData", info.iconData);
            appInfo.put("iconUrl", info.iconUrl);
            appsList.add(appInfo);
        }
        result.success(appsList);
    }

    private String resolvePackageName(MethodCall call) {
        String packageName = call.argument("packageName");
        if (packageName == null || packageName.isEmpty()) {
            packageName = signerPackageName;
        }
        return packageName;
    }

    private void setPackageName(MethodCall call, SafeResult result) {
        String packageName = resolvePackageName(call);
        if (packageName == null || packageName.isEmpty()) {
            result.error("ERROR", "Missing or empty packageName parameter", null);
            return;
        }
        signerPackageName = packageName;
        result.success(null);
    }

    private void getPublicKey(MethodCall call, SafeResult result) {
        String packageName = resolvePackageName(call);
        if (!requirePackage(packageName, result)) return;

        String publicKey = Signer.getPublicKey(context, packageName);
        if (publicKey != null) {
            Map<String, Object> ret = new HashMap<>();
            ret.put("npub", publicKey);
            ret.put("package", packageName);
            result.success(ret);
            return;
        }
        if (!requireActivityHandler(result)) return;
        String permissions = call.argument("permissions");
        Intent intent = IntentBuilder.getPublicKeyIntent(packageName, permissions);
        activityResultHandler.launch(intent, ar -> handleActivityResult(ar, result));
    }

    private void signEvent(MethodCall call, SafeResult result) {
        String packageName = resolvePackageName(call);
        if (!requirePackage(packageName, result)) return;

        String eventJson = call.argument("eventJson");
        String eventId = call.argument("eventId");
        String npub = call.argument("npub");
        if (eventJson == null || eventId == null || npub == null) {
            result.error("ERROR", "Missing parameters", null);
            return;
        }
        String[] signed = Signer.signEvent(context, packageName, eventJson, npub);
        if (signed != null) {
            Map<String, Object> ret = new HashMap<>();
            ret.put("signature", signed[0]);
            ret.put("id", eventId);
            ret.put("event", signed[1]);
            result.success(ret);
            return;
        }
        if (!requireActivityHandler(result)) return;
        Intent intent = IntentBuilder.signEventIntent(packageName, eventJson, eventId, npub);
        activityResultHandler.launch(intent, ar -> handleActivityResult(ar, result));
    }

    private void nip04Encrypt(MethodCall call, SafeResult result) {
        String packageName = resolvePackageName(call);
        if (!requirePackage(packageName, result)) return;

        String plainText = call.argument("plainText");
        String pubKey = call.argument("pubKey");
        String npub = call.argument("npub");
        String id = call.argument("id");
        if (plainText == null || pubKey == null || npub == null) {
            result.error("ERROR", "Missing parameters", null);
            return;
        }
        String encrypted = Signer.nip04Encrypt(context, packageName, plainText, pubKey, npub);
        if (encrypted != null) {
            Map<String, Object> ret = new HashMap<>();
            ret.put("result", encrypted);
            ret.put("id", id);
            result.success(ret);
            return;
        }
        if (!requireActivityHandler(result)) return;
        Intent intent = IntentBuilder.nip04EncryptIntent(packageName, plainText, id, npub, pubKey);
        activityResultHandler.launch(intent, ar -> handleActivityResult(ar, result));
    }

    private void nip04Decrypt(MethodCall call, SafeResult result) {
        String packageName = resolvePackageName(call);
        if (!requirePackage(packageName, result)) return;

        String encryptedText = call.argument("encryptedText");
        String pubKey = call.argument("pubKey");
        String npub = call.argument("npub");
        String id = call.argument("id");
        if (encryptedText == null || pubKey == null || npub == null) {
            result.error("ERROR", "Missing parameters", null);
            return;
        }
        String decrypted = Signer.nip04Decrypt(context, packageName, encryptedText, pubKey, npub);
        if (decrypted != null) {
            Map<String, Object> ret = new HashMap<>();
            ret.put("result", decrypted);
            ret.put("id", id);
            result.success(ret);
            return;
        }
        if (!requireActivityHandler(result)) return;
        Intent intent = IntentBuilder.nip04DecryptIntent(packageName, encryptedText, id, pubKey, npub);
        activityResultHandler.launch(intent, ar -> handleActivityResult(ar, result));
    }

    private void nip44Encrypt(MethodCall call, SafeResult result) {
        String packageName = resolvePackageName(call);
        if (!requirePackage(packageName, result)) return;

        String plainText = call.argument("plainText");
        String pubKey = call.argument("pubKey");
        String npub = call.argument("npub");
        String id = call.argument("id");
        if (plainText == null || pubKey == null || npub == null) {
            result.error("ERROR", "Missing parameters", null);
            return;
        }
        String encrypted = Signer.nip44Encrypt(context, packageName, plainText, pubKey, npub);
        if (encrypted != null) {
            Map<String, Object> ret = new HashMap<>();
            ret.put("result", encrypted);
            ret.put("id", id);
            result.success(ret);
            return;
        }
        if (!requireActivityHandler(result)) return;
        // Note: upstream uses nip04EncryptIntent here; preserved for behavior parity.
        Intent intent = IntentBuilder.nip04EncryptIntent(packageName, plainText, id, npub, pubKey);
        activityResultHandler.launch(intent, ar -> handleActivityResult(ar, result));
    }

    private void nip44Decrypt(MethodCall call, SafeResult result) {
        String packageName = resolvePackageName(call);
        if (!requirePackage(packageName, result)) return;

        String encryptedText = call.argument("encryptedText");
        String pubKey = call.argument("pubKey");
        String npub = call.argument("npub");
        String id = call.argument("id");
        if (encryptedText == null || pubKey == null || npub == null) {
            result.error("ERROR", "Missing parameters", null);
            return;
        }
        String decrypted = Signer.nip44Decrypt(context, packageName, encryptedText, pubKey, npub);
        if (decrypted != null) {
            Map<String, Object> ret = new HashMap<>();
            ret.put("result", decrypted);
            ret.put("id", id);
            result.success(ret);
            return;
        }
        if (!requireActivityHandler(result)) return;
        Intent intent = IntentBuilder.nip44DecryptIntent(packageName, encryptedText, id, pubKey, npub);
        activityResultHandler.launch(intent, ar -> handleActivityResult(ar, result));
    }

    private void decryptZapEvent(MethodCall call, SafeResult result) {
        String packageName = resolvePackageName(call);
        if (!requirePackage(packageName, result)) return;

        String eventJson = call.argument("eventJson");
        String npub = call.argument("npub");
        String id = call.argument("id");
        if (eventJson == null || npub == null) {
            result.error("ERROR", "Missing parameters", null);
            return;
        }
        String decrypted = Signer.decryptZapEvent(context, packageName, eventJson, npub);
        if (decrypted != null) {
            Map<String, Object> ret = new HashMap<>();
            ret.put("result", decrypted);
            ret.put("id", id);
            result.success(ret);
            return;
        }
        if (!requireActivityHandler(result)) return;
        Intent intent = IntentBuilder.decryptZapEventIntent(packageName, eventJson, id, npub);
        activityResultHandler.launch(intent, ar -> handleActivityResult(ar, result));
    }

    private void getRelays(MethodCall call, SafeResult result) {
        String packageName = resolvePackageName(call);
        if (!requirePackage(packageName, result)) return;

        String npub = call.argument("current_user");
        String id = call.argument("id");
        if (npub == null) {
            result.error("ERROR", "Missing parameters", null);
            return;
        }
        String relayJson = Signer.getRelays(context, packageName, npub);
        if (relayJson != null) {
            Map<String, Object> ret = new HashMap<>();
            ret.put("result", relayJson);
            ret.put("id", id);
            result.success(ret);
            return;
        }
        if (!requireActivityHandler(result)) return;
        Intent intent = IntentBuilder.getRelaysIntent(packageName, id, npub);
        activityResultHandler.launch(intent, ar -> handleActivityResult(ar, result));
    }

    // ───── Helpers ────────────────────────────────────────────────────────────

    private boolean requirePackage(String packageName, SafeResult result) {
        if (packageName == null || packageName.isEmpty()) {
            result.error("ERROR", "Signer package name not set. Call setPackageName first.", null);
            return false;
        }
        return true;
    }

    private boolean requireActivityHandler(SafeResult result) {
        if (activityResultHandler == null || activity == null) {
            result.error("NO_ACTIVITY", "Plugin is not attached to an activity", null);
            return false;
        }
        return true;
    }

    private void handleActivityResult(ActivityResult activityResult, SafeResult result) {
        Intent data = activityResult.getData();
        if (data != null) {
            Bundle extras = data.getExtras();
            Map<String, Object> resultData = new HashMap<>();
            if (extras != null) {
                for (String key : extras.keySet()) {
                    resultData.put(key, extras.get(key));
                }
            }
            result.success(resultData);
        } else {
            result.error("NO_DATA", "No data returned from activity.", null);
        }
    }
}
