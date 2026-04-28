package dev.purplebase.amber_signer;

import android.os.Handler;
import android.util.Log;

import androidx.annotation.Nullable;

import java.util.concurrent.atomic.AtomicBoolean;

import io.flutter.plugin.common.MethodChannel;

/**
 * One-shot wrapper around a {@link MethodChannel.Result}.
 *
 * <p>Flutter's {@code MethodChannel.Result} contract is single-use: invoking
 * {@link MethodChannel.Result#success(Object)}, {@link MethodChannel.Result#error}, or
 * {@link MethodChannel.Result#notImplemented()} more than once throws
 * {@code IllegalStateException("Reply already submitted")}, which crashes the activity
 * because the exception bubbles up through {@code Activity.dispatchActivityResult}.
 *
 * <p>{@code SafeResult} guards every reply path with an {@link AtomicBoolean}; the second
 * (and any subsequent) reply is silently dropped and logged. Replies are also marshalled to
 * the main thread, since {@code MethodChannel.Result} is only safe to call from there.
 *
 * <p>Subclasses can override {@link #onFinished()} to drop the result from any tracking
 * structure once it has been settled.
 */
abstract class SafeResult implements MethodChannel.Result {

    private static final String TAG = "AmberSignerSafeResult";

    private final MethodChannel.Result delegate;
    private final Handler mainHandler;
    private final AtomicBoolean closed = new AtomicBoolean(false);

    SafeResult(MethodChannel.Result delegate, Handler mainHandler) {
        this.delegate = delegate;
        this.mainHandler = mainHandler;
    }

    /** Called exactly once, after the first successful reply, on the main thread. */
    abstract void onFinished();

    @Override
    public void success(@Nullable Object result) {
        if (!closed.compareAndSet(false, true)) {
            Log.w(TAG, "Dropping duplicate success() reply");
            return;
        }
        runOnMain(() -> {
            try {
                delegate.success(result);
            } catch (Throwable t) {
                Log.e(TAG, "delegate.success threw", t);
            } finally {
                safeOnFinished();
            }
        });
    }

    @Override
    public void error(String errorCode, @Nullable String errorMessage, @Nullable Object errorDetails) {
        if (!closed.compareAndSet(false, true)) {
            Log.w(TAG, "Dropping duplicate error() reply (" + errorCode + ")");
            return;
        }
        runOnMain(() -> {
            try {
                delegate.error(errorCode, errorMessage, errorDetails);
            } catch (Throwable t) {
                Log.e(TAG, "delegate.error threw", t);
            } finally {
                safeOnFinished();
            }
        });
    }

    @Override
    public void notImplemented() {
        if (!closed.compareAndSet(false, true)) {
            Log.w(TAG, "Dropping duplicate notImplemented() reply");
            return;
        }
        runOnMain(() -> {
            try {
                delegate.notImplemented();
            } catch (Throwable t) {
                Log.e(TAG, "delegate.notImplemented threw", t);
            } finally {
                safeOnFinished();
            }
        });
    }

    private void runOnMain(Runnable r) {
        if (Thread.currentThread() == mainHandler.getLooper().getThread()) {
            r.run();
        } else {
            mainHandler.post(r);
        }
    }

    private void safeOnFinished() {
        try {
            onFinished();
        } catch (Throwable t) {
            Log.w(TAG, "onFinished hook threw", t);
        }
    }
}
