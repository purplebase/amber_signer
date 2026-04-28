package dev.purplebase.amber_signer;

import android.app.Activity;
import android.content.Intent;

import androidx.activity.result.ActivityResult;

import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding;

/**
 * Launches an Intent for an activity result and routes the result back to a one-shot callback.
 * Implementations MUST guarantee that {@link ActivityResultCallback#onActivityResult} is invoked
 * at most once per launch, even across activity recreation, and MUST flush all pending callbacks
 * with a synthetic cancelled result on {@link #dispose()}.
 */
public interface ActivityResultHandler {
    void init(Activity activity, ActivityPluginBinding binding);

    /**
     * Launches the given intent. The callback will be invoked exactly once: either with the
     * activity result, or with a synthetic cancelled result if the handler is disposed or
     * {@link #cancelAll()} is called before the result arrives.
     */
    void launch(Intent intent, ActivityResultCallback callback);

    /**
     * Flushes all pending callbacks with a synthetic cancelled {@link ActivityResult}
     * (resultCode = {@link Activity#RESULT_CANCELED}, data = null). Safe to call multiple times.
     */
    void cancelAll();

    void dispose();

    interface ActivityResultCallback {
        void onActivityResult(ActivityResult result);
    }
}
