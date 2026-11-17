package dev.blackwall;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.VpnService;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.os.SystemClock;
import android.system.OsConstants;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The link to the core (libblackwall.so, src/android/session.zig): one
 * socket pair, a line of JSON each way. The core keeps the configuration
 * and carries the traffic; this class answers what only Android knows (who
 * owns a connection, what a subscription address returns, which resolvers
 * the network has) and hands everything else to its listeners.
 */
final class Core {
    interface Listener {
        /** On the main thread. */
        void onCore(String ev, JSONObject o);
    }

    private static Core self;

    static synchronized Core get(Context c) {
        if (self == null) self = new Core(c.getApplicationContext());
        return self;
    }

    static {
        System.loadLibrary("blackwall");
    }

    private static native void start(int fd);

    /** The QR code in a grayscale picture (w×h bytes): its length in `out`, or -1. */
    private static native int qr(java.nio.ByteBuffer gray, int w, int h, java.nio.ByteBuffer out);

    /** `in` (n bytes of UTF-8) without secrets into `out`: its length, or -1 (src/core/diag.zig). */
    private static native int scrub(java.nio.ByteBuffer in, int n, java.nio.ByteBuffer out);

    /** The text without links, keys, or the names and addresses of servers and sites; null if it fails. */
    static String scrubbed(String text) {
        byte[] b = text.getBytes(StandardCharsets.UTF_8);
        java.nio.ByteBuffer in = java.nio.ByteBuffer.allocateDirect(Math.max(1, b.length));
        in.put(b);
        // a short name can become a longer token
        java.nio.ByteBuffer out = java.nio.ByteBuffer.allocateDirect(b.length * 2 + 4096);
        int n = scrub(in, b.length, out);
        if (n < 0) return null;
        byte[] r = new byte[n];
        out.get(r, 0, n);
        return new String(r, StandardCharsets.UTF_8);
    }

    /** The text of a QR code in `gray` (a direct buffer of w×h bytes), or null. */
    static String readQr(java.nio.ByteBuffer gray, int w, int h) {
        java.nio.ByteBuffer out = java.nio.ByteBuffer.allocateDirect(4096);
        int n = qr(gray, w, h, out);
        if (n <= 0) return null;
        byte[] b = new byte[n];
        out.get(b, 0, n);
        return new String(b, StandardCharsets.UTF_8);
    }

    final Context app;
    private final Handler main = new Handler(Looper.getMainLooper());
    private final ExecutorService out = Executors.newSingleThreadExecutor();
    private final ExecutorService downloads = Executors.newFixedThreadPool(2);
    private final ArrayList<Listener> listeners = new ArrayList<>();
    private ParcelFileDescriptor end;
    private OutputStream os;

    /** The latest of each, for whoever starts listening later. */
    JSONObject state = new JSONObject(), status = new JSONObject(), plan;
    /** Bytes per second, from the last two status reports. */
    double rateDown, rateUp;
    /** When the VPN came up (elapsedRealtime), 0 while it is not. */
    long upSince;
    private long lastDown, lastUp, lastAt;
    private boolean restored;

    private Core(Context app) {
        this.app = app;
        try {
            ParcelFileDescriptor[] pair = ParcelFileDescriptor.createSocketPair();
            end = pair[0];
            os = new FileOutputStream(end.getFileDescriptor());
            start(pair[1].detachFd());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        Thread reader = new Thread(this::read, "core");
        reader.setDaemon(true);
        reader.start();
        send("init", "dir", app.getFilesDir().getAbsolutePath());
        watchNetwork();
    }

    void listen(Listener l) {
        if (!listeners.contains(l)) listeners.add(l);
    }

    void unlisten(Listener l) {
        listeners.remove(l);
    }

    /** send("rule", "app", pkg, "route", "direct") */
    void send(String cmd, Object... kv) {
        JSONObject o = new JSONObject();
        try {
            o.put("cmd", cmd);
            for (int i = 0; i + 1 < kv.length; i += 2) o.put((String) kv[i], kv[i + 1]);
        } catch (JSONException e) {
            return;
        }
        byte[] line = (o + "\n").getBytes(StandardCharsets.UTF_8);
        out.execute(() -> {
            try {
                os.write(line);
            } catch (IOException e) {
                Log.e("blackwall", "the core is gone", e);
            }
        });
    }

    private void read() {
        try (BufferedReader r = new BufferedReader(
                new InputStreamReader(new FileInputStream(end.getFileDescriptor()), StandardCharsets.UTF_8), 1 << 16)) {
            String line;
            while ((line = r.readLine()) != null) {
                final JSONObject o;
                try {
                    o = new JSONObject(line);
                } catch (JSONException e) {
                    continue;
                }
                final String ev = o.optString("ev");
                switch (ev) {
                    // a flow waits for this one: answered right here
                    case "owner":
                        owner(o);
                        break;
                    case "fetch":
                        downloads.execute(() -> fetch(o));
                        break;
                    default:
                        main.post(() -> deliver(ev, o));
                }
            }
        } catch (IOException e) {
            Log.e("blackwall", "the core is gone", e);
        }
    }

    private void deliver(String ev, JSONObject o) {
        switch (ev) {
            case "state":
                state = o;
                if (!restored) {
                    restored = true;
                    restore();
                }
                break;
            case "status":
                onStatus(o);
                break;
            case "plan":
                plan = o;
                Tunnel.apply(app, o);
                break;
        }
        for (Listener l : new ArrayList<>(listeners)) l.onCore(ev, o);
    }

    /**
     * This process has just started. If the VPN was on, or applications
     * were being held, when the last one went away (the device restarted,
     * the app was updated or killed), it comes back without being asked.
     */
    private void restore() {
        if (Tunnel.running()) return; // the system started it: it speaks for itself
        if (VpnService.prepare(app) != null) return; // not this device's VPN (any more)
        if (Tunnel.prefs(app).getBoolean("on", false)) send("connect");
        else if (state.optBoolean("standby")) send("disconnect");
    }

    private void onStatus(JSONObject o) {
        long now = SystemClock.elapsedRealtime();
        boolean carrying = o.optBoolean("up") && !o.optBoolean("standby");
        long down = o.optLong("down"), up = o.optLong("sent");
        if (carrying && upSince != 0 && now > lastAt && down >= lastDown) {
            // after a quiet spell (no status while nothing moved) the bytes
            // are from the last second only
            double dt = Math.min((now - lastAt) / 1000.0, 1.0);
            rateDown = (down - lastDown) / dt;
            rateUp = (up - lastUp) / dt;
        } else {
            rateDown = rateUp = 0;
        }
        if (!carrying) upSince = 0;
        else if (upSince == 0) upSince = now;
        lastDown = down;
        lastUp = up;
        lastAt = now;
        status = o;
    }

    /** Which application owns a connection the tunnel sees (Android 10+). */
    private void owner(JSONObject o) {
        JSONArray apps = new JSONArray();
        try {
            ConnectivityManager cm = app.getSystemService(ConnectivityManager.class);
            int proto = o.optBoolean("udp") ? OsConstants.IPPROTO_UDP : OsConstants.IPPROTO_TCP;
            InetSocketAddress local = new InetSocketAddress(InetAddress.getByName(o.getString("la")), o.getInt("lp"));
            InetSocketAddress remote = new InetSocketAddress(InetAddress.getByName(o.getString("ra")), o.getInt("rp"));
            int uid = cm.getConnectionOwnerUid(proto, local, remote);
            if (uid != Process.INVALID_UID) {
                String[] packages = app.getPackageManager().getPackagesForUid(uid);
                if (packages != null) for (String p : packages) apps.put(p);
            }
        } catch (Exception e) {
            // nobody's flow: the core applies the default
        }
        send("owner", "q", o.optInt("q"), "apps", apps);
    }

    private static final int BODY_MAX = 4 << 20;

    /** A subscription's body, through the system's HTTP stack and trust store. */
    private void fetch(JSONObject o) {
        String text = null;
        HttpURLConnection c = null;
        try {
            c = (HttpURLConnection) new URL(o.getString("url")).openConnection();
            c.setConnectTimeout(15000);
            c.setReadTimeout(20000);
            c.setRequestProperty("User-Agent", "blackwall/" + version(app));
            if (c.getResponseCode() == 200) {
                try (InputStream in = c.getInputStream()) {
                    ByteArrayOutputStream body = new ByteArrayOutputStream();
                    byte[] buf = new byte[16384];
                    int n;
                    while ((n = in.read(buf)) > 0 && body.size() <= BODY_MAX) body.write(buf, 0, n);
                    if (body.size() <= BODY_MAX) text = body.toString("UTF-8");
                }
            }
        } catch (Exception e) {
            // reported as a failed update
        } finally {
            if (c != null) c.disconnect();
        }
        if (text != null) send("body", "id", o.optInt("id"), "text", text);
        else send("body", "id", o.optInt("id"));
    }

    /**
     * The resolvers of the network under the VPN. This app is left out of
     * its own VPN, so its default network is that one.
     */
    private void watchNetwork() {
        ConnectivityManager cm = app.getSystemService(ConnectivityManager.class);
        try {
            cm.registerDefaultNetworkCallback(new ConnectivityManager.NetworkCallback() {
                @Override
                public void onLinkPropertiesChanged(Network network, LinkProperties lp) {
                    JSONArray dns = new JSONArray();
                    for (InetAddress a : lp.getDnsServers()) {
                        if (a instanceof Inet4Address) dns.put(a.getHostAddress());
                    }
                    send("net", "dns", dns);
                }
            });
        } catch (RuntimeException e) {
            // public resolvers stand in
        }
    }

    static String version(Context c) {
        try {
            return c.getPackageManager().getPackageInfo(c.getPackageName(), 0).versionName;
        } catch (Exception e) {
            return "";
        }
    }

    /** The server with this id in the latest state, or null. */
    JSONObject server(int id) {
        JSONArray list = state.optJSONArray("servers");
        if (list == null || id == 0) return null;
        for (int i = 0; i < list.length(); i++) {
            JSONObject s = list.optJSONObject(i);
            if (s != null && s.optInt("id") == id) return s;
        }
        return null;
    }
}
