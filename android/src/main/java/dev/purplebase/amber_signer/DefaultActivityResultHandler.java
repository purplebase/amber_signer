package dev.purplebase.amber_signer;

import android.app.Activity;
import android.content.Intent;
import android.util.Log;

import androidx.activity.result.ActivityResult;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding;
import io.flutter.plugin.common.PluginRegistry;

/**
 * Default {@link ActivityResultHandler} backed by {@code Activity.startActivityForResult}
 * and a {@link PluginRegistry.ActivityResultListener} registered on the plugin binding.
 *
 * <p>Bug-for-bug compatible with the upstream signer_plugin handler, with these fixes:
 * <ul>
 *   <li>Each launch gets a unique request code; callbacks are routed via that code only.
 *   <li>Callbacks are removed from the map before invocation, so a double-delivered
 *       activity result cannot invoke the same callback twice.
 *   <li>{@link #cancelAll()} and {@link #dispose()} flush every in-flight callback with a
 *       synthetic {@link Activity#RESULT_CANCELED} result so Dart awaiters receive a
 *       deterministic outcome instead of leaking forever.
 *   <li>This handler does NOT use {@code ActivityResultLauncher}; mixing the AndroidX
 *       launcher (which uses {@code requestCode == -1}) with the legacy
 *       {@code onActivityResult} path is the root cause of the
 *       "Reply already submitted" crash observed in the upstream plugin.
 * </ul>
 */
public class DefaultActivityResultHandler
        implements ActivityResultHandler, PluginRegistry.ActivityResultListener {

    private static final String TAG = "AmberSignerARH";
    private static final int REQUEST_CODE_BASE = 0xA50000; // arbitrary, unlikely to collide

    private Activity activity;
    private ActivityPluginBinding binding;

    /** LinkedHashMap to preserve launch order for deterministic flushing. */
    private final Map<Integer, ActivityResultCallback> callbackMap = new LinkedHashMap<>();
    private int requestCodeCounter = REQUEST_CODE_BASE;

    @Override
    public void init(Activity activity, ActivityPluginBinding binding) {
        this.activity = activity;
        this.binding = binding;
        binding.addActivityResultListener(this);
    }

    @Override
    public void launch(Intent intent, ActivityResultCallback callback) {
        if (activity == null) {
            Log.w(TAG, "launch() called with no activity; cancelling callback");
            callback.onActivityResult(new ActivityResult(Activity.RESULT_CANCELED, null));
            return;
        }
        final int requestCode = generateRequestCode();
        callbackMap.put(requestCode, callback);
        try {
            activity.startActivityForResult(intent, requestCode);
        } catch (Throwable t) {
            // If the launch fails synchronously, we must release the callback ourselves —
            // otherwise the Dart side hangs forever.
            callbackMap.remove(requestCode);
            Log.w(TAG, "startActivityForResult failed", t);
            callback.onActivityResult(new ActivityResult(Activity.RESULT_CANCELED, null));
        }
    }

    @Override
    public boolean onActivityResult(int requestCode, int resultCode, Intent data) {
        // Remove BEFORE invoking, so any re-delivery of the same requestCode cannot
        // re-trigger the callback (defense against framework re-dispatch on recreation).
        ActivityResultCallback callback = callbackMap.remove(requestCode);
        if (callback == null) {
            return false;
        }
        try {
            callback.onActivityResult(new ActivityResult(resultCode, data));
        } catch (Throwable t) {
            Log.e(TAG, "Activity result callback threw", t);
        }
        return true;
    }

    @Override
    public void cancelAll() {
        if (callbackMap.isEmpty()) return;
        // Snapshot and clear first so callbacks that re-enter the handler don't see stale state.
        Map<Integer, ActivityResultCallback> pending = new HashMap<>(callbackMap);
        callbackMap.clear();
        ActivityResult cancelled = new ActivityResult(Activity.RESULT_CANCELED, null);
        for (ActivityResultCallback cb : pending.values()) {
            try {
                cb.onActivityResult(cancelled);
            } catch (Throwable t) {
                Log.w(TAG, "Pending callback threw on cancelAll", t);
            }
        }
    }

    private int generateRequestCode() {
        // Stay within the 16-bit range required by FragmentActivity.
        if (requestCodeCounter > 0xFFFF) {
            requestCodeCounter = REQUEST_CODE_BASE & 0xFFFF;
        }
        return requestCodeCounter++ & 0xFFFF;
    }

    @Override
    public void dispose() {
        cancelAll();
        if (binding != null) {
            binding.removeActivityResultListener(this);
            binding = null;
        }
        activity = null;
    }
}
