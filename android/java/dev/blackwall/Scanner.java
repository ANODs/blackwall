package dev.blackwall;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.ImageFormat;
import android.graphics.SurfaceTexture;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.hardware.camera2.CaptureRequest;
import android.media.Image;
import android.media.ImageReader;
import android.net.Uri;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.SystemClock;
import android.view.Surface;
import android.view.TextureView;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * A QR code from the camera (Camera2, the Y plane of each frame read by the
 * core's reader, src/core/qr.zig) or from a picture. Nothing leaves the
 * phone: the frames are read in this process and dropped.
 */
final class Scanner {
    interface Found {
        /** On the main thread; null when the scan was closed without a code. */
        void text(String text);
    }

    /** A picture chosen by the user (a screenshot, an image from a chat). */
    static String fromPicture(Context c, Uri uri) {
        try (InputStream in = c.getContentResolver().openInputStream(uri)) {
            BitmapFactory.Options o = new BitmapFactory.Options();
            o.inJustDecodeBounds = true;
            BitmapFactory.decodeStream(in, null, o);
            int scale = 1;
            while (o.outWidth / scale > 2048 || o.outHeight / scale > 2048) scale *= 2;
            o = new BitmapFactory.Options();
            o.inSampleSize = scale;
            try (InputStream in2 = c.getContentResolver().openInputStream(uri)) {
                Bitmap b = BitmapFactory.decodeStream(in2, null, o);
                if (b == null) return null;
                int w = b.getWidth(), h = b.getHeight();
                int[] px = new int[w * h];
                b.getPixels(px, 0, w, 0, 0, w, h);
                b.recycle();
                ByteBuffer gray = ByteBuffer.allocateDirect(w * h);
                for (int p : px) gray.put((byte) ((((p >> 16) & 0xff) * 77 + ((p >> 8) & 0xff) * 150 + (p & 0xff) * 29) >> 8));
                return Core.readQr(gray, w, h);
            }
        } catch (Exception e) {
            return null;
        }
    }

    private final Activity activity;
    private final Found found;
    private final Dialog dialog;
    private final TextureView view;
    private final HandlerThread thread = new HandlerThread("scanner");
    private Handler bg;
    private CameraDevice camera;
    private CameraCaptureSession session;
    private ImageReader reader;
    private ByteBuffer gray;
    private long last;
    private volatile boolean done;

    Scanner(Activity activity, Found found) {
        this.activity = activity;
        this.found = found;
        view = new TextureView(activity);
        dialog = new Dialog(activity, android.R.style.Theme_Black_NoTitleBar_Fullscreen);
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
        dialog.setContentView(view, new ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        dialog.getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        dialog.setOnDismissListener(d -> finish(null));
        view.setOnClickListener(v -> dialog.dismiss());
    }

    void show() {
        thread.start();
        bg = new Handler(thread.getLooper());
        dialog.show();
        view.setSurfaceTextureListener(new TextureView.SurfaceTextureListener() {
            @Override
            public void onSurfaceTextureAvailable(SurfaceTexture st, int w, int h) {
                open(st);
            }

            @Override
            public void onSurfaceTextureSizeChanged(SurfaceTexture st, int w, int h) {
            }

            @Override
            public boolean onSurfaceTextureDestroyed(SurfaceTexture st) {
                return true;
            }

            @Override
            public void onSurfaceTextureUpdated(SurfaceTexture st) {
            }
        });
    }

    private void open(SurfaceTexture st) {
        CameraManager cm = activity.getSystemService(CameraManager.class);
        try {
            String id = null;
            for (String c : cm.getCameraIdList()) {
                Integer facing = cm.getCameraCharacteristics(c).get(CameraCharacteristics.LENS_FACING);
                if (facing != null && facing == CameraCharacteristics.LENS_FACING_BACK) {
                    id = c;
                    break;
                }
            }
            if (id == null && cm.getCameraIdList().length > 0) id = cm.getCameraIdList()[0];
            if (id == null) {
                dialog.dismiss();
                return;
            }
            final int w = 1280, h = 720;
            st.setDefaultBufferSize(w, h);
            reader = ImageReader.newInstance(w, h, ImageFormat.YUV_420_888, 2);
            reader.setOnImageAvailableListener(this::frame, bg);
            cm.openCamera(id, new CameraDevice.StateCallback() {
                @Override
                public void onOpened(CameraDevice cd) {
                    camera = cd;
                    start(new Surface(st));
                }

                @Override
                public void onDisconnected(CameraDevice cd) {
                    cd.close();
                }

                @Override
                public void onError(CameraDevice cd, int error) {
                    cd.close();
                    activity.runOnUiThread(dialog::dismiss);
                }
            }, bg);
        } catch (SecurityException | android.hardware.camera2.CameraAccessException e) {
            dialog.dismiss();
        }
    }

    @SuppressWarnings("deprecation")
    private void start(Surface preview) {
        try {
            final CaptureRequest.Builder rq = camera.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW);
            rq.addTarget(preview);
            rq.addTarget(reader.getSurface());
            rq.set(CaptureRequest.CONTROL_AF_MODE, CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE);
            camera.createCaptureSession(Arrays.asList(preview, reader.getSurface()), new CameraCaptureSession.StateCallback() {
                @Override
                public void onConfigured(CameraCaptureSession s) {
                    session = s;
                    try {
                        s.setRepeatingRequest(rq.build(), null, bg);
                    } catch (Exception e) {
                        activity.runOnUiThread(dialog::dismiss);
                    }
                }

                @Override
                public void onConfigureFailed(CameraCaptureSession s) {
                    activity.runOnUiThread(dialog::dismiss);
                }
            }, bg);
        } catch (Exception e) {
            activity.runOnUiThread(dialog::dismiss);
        }
    }

    /** A frame: its brightness, read a few times a second. */
    private void frame(ImageReader r) {
        Image img = r.acquireLatestImage();
        if (img == null) return;
        try {
            long now = SystemClock.elapsedRealtime();
            if (done || now - last < 250) return;
            last = now;
            Image.Plane y = img.getPlanes()[0];
            int w = img.getWidth(), h = img.getHeight();
            if (gray == null || gray.capacity() != w * h) gray = ByteBuffer.allocateDirect(w * h);
            ByteBuffer src = y.getBuffer();
            int stride = y.getRowStride();
            byte[] row = new byte[w];
            gray.clear();
            for (int line = 0; line < h; line++) {
                src.position(line * stride);
                src.get(row, 0, w);
                gray.put(row);
            }
            String text = Core.readQr(gray, w, h);
            if (text != null) {
                done = true;
                activity.runOnUiThread(() -> {
                    finish(text);
                    dialog.dismiss();
                });
            }
        } catch (Exception ignored) {
        } finally {
            img.close();
        }
    }

    private boolean finished;

    private void finish(String text) {
        if (finished) return;
        finished = true;
        if (session != null) session.close();
        if (camera != null) camera.close();
        if (reader != null) reader.close();
        thread.quitSafely();
        found.text(text);
    }
}
