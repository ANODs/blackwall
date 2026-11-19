package dev.blackwall;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.os.PowerManager;
import android.os.SystemClock;
import android.system.OsConstants;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Locale;

/**
 * The VPN as Android sees it. The core decides what it must look like (a
 * "plan": which applications are in, what happens to IPv6); this service
 * establishes exactly that and gives the TUN descriptor to the core.
 *
 * Applications sent "direct" are left out, so they never touch the tunnel.
 * After Disconnect the VPN may stay up for the applications that must not
 * reach the network without it: only they are let in, and the core refuses
 * everything there. This app itself is always outside, which is how the
 * core's own connections reach the servers.
 */
public class Tunnel extends VpnService implements Core.Listener {
    static final String APPLY = "dev.blackwall.APPLY";
    private static final String OFF = "dev.blackwall.OFF", ON = "dev.blackwall.ON";
    private static final String CHANNEL = "vpn";
    private static final int NOTE = 1;

    private static Tunnel instance;

    private Core core;
    private String shown = "";

    static boolean running() {
        return instance != null;
    }

    /** The user's switch, kept so a restarted process knows what to restore. */
    static SharedPreferences prefs(Context c) {
        return c.getSharedPreferences("shell", MODE_PRIVATE);
    }

    /** Bring the VPN in line with a plan from the core. */
    static void apply(Context c, JSONObject plan) {
        if (!plan.optBoolean("need")) {
            Core.get(c).send("down");
            if (instance != null) instance.finish();
        } else if (instance != null) {
            instance.establish(plan);
        } else {
            c.startForegroundService(new Intent(c, Tunnel.class).setAction(APPLY));
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        instance = this;
        core = Core.get(this);
        core.listen(this);
        NotificationChannel ch = new NotificationChannel(CHANNEL, "VPN", NotificationManager.IMPORTANCE_LOW);
        ch.setShowBadge(false);
        getSystemService(NotificationManager.class).createNotificationChannel(ch);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (Build.VERSION.SDK_INT >= 34) startForeground(NOTE, note(), ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED);
        else startForeground(NOTE, note());
        String action = intent == null ? null : intent.getAction();
        if (APPLY.equals(action)) {
            establish(core.plan);
        } else if (OFF.equals(action)) {
            // the notification's switch
            prefs(this).edit().putBoolean("on", false).apply();
            core.send("disconnect");
        } else if (ON.equals(action)) {
            if (prepare(this) == null) {
                prefs(this).edit().putBoolean("on", true).apply();
                core.send("connect");
            }
        } else {
            // by the system: "Always-on VPN", or this process was restarted.
            // The core answers with a plan either way.
            boolean on = SERVICE_INTERFACE.equals(action) || prefs(this).getBoolean("on", false);
            if (SERVICE_INTERFACE.equals(action)) prefs(this).edit().putBoolean("on", true).apply();
            core.send(on ? "connect" : "disconnect");
        }
        return START_STICKY;
    }

    private void establish(JSONObject plan) {
        if (plan == null || !plan.optBoolean("need")) return;
        // the consent can be taken back at any time
        if (prepare(this) != null) {
            gone();
            return;
        }
        int mtu = plan.optInt("mtu", 1500);
        Builder b = new Builder()
                .setSession("BLACKWALL")
                .setMtu(mtu)
                // the whole range the core hands out names from, as on the
                // desktop: in a smaller subnet one of those addresses would
                // be its broadcast address
                .addAddress("198.18.0.1", 15)
                .addDnsServer("198.18.0.2")
                .setMetered(false)
                .setConfigureIntent(open());
        try {
            if (plan.optBoolean("lan")) {
                // the router, printers and casting stay reachable, as on a computer
                for (String r : outsideLan()) {
                    String[] p = r.split("/");
                    b.addRoute(p[0], Integer.parseInt(p[1]));
                }
            } else {
                b.addRoute("0.0.0.0", 0);
            }
            // "block" needs nothing: a family the VPN has no address for is refused
            switch (plan.optString("ipv6")) {
                case "tunnel":
                    b.addAddress("fd00:b1ac:3a11::1", 126).addRoute("::", 0);
                    break;
                case "system":
                    b.allowFamily(OsConstants.AF_INET6);
                    break;
            }
            JSONArray only = plan.optJSONArray("only");
            JSONArray except = plan.optJSONArray("except");
            if (only != null && only.length() > 0) {
                int in = 0;
                for (int i = 0; i < only.length(); i++) {
                    try {
                        b.addAllowedApplication(only.getString(i));
                        in++;
                    } catch (PackageManager.NameNotFoundException e) {
                        // uninstalled since the rule was made
                    }
                }
                // an empty list would let everything in, this app included
                if (in == 0) {
                    core.send("down");
                    finish();
                    return;
                }
            } else {
                b.addDisallowedApplication(getPackageName());
                for (int i = 0; except != null && i < except.length(); i++) {
                    try {
                        b.addDisallowedApplication(except.getString(i));
                    } catch (PackageManager.NameNotFoundException e) {
                        // uninstalled
                    }
                }
            }
            // a new interface takes over from the one in use without a gap
            ParcelFileDescriptor tun = b.establish();
            if (tun == null) {
                gone();
                return;
            }
            core.send("up", "fd", tun.detachFd(), "mtu", mtu);
        } catch (Exception e) {
            gone();
        }
    }

    /** Local, link-local and multicast IPv4: what stays outside the VPN. */
    private static final String[] LAN = {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32"};

    /**
     * Every IPv4 prefix outside {@link #LAN}, as few as possible: each half
     * of a range that overlaps the local ones is split again. Works on every
     * Android version (Builder.excludeRoute needs 13).
     */
    static java.util.List<String> outsideLan() {
        long[][] lan = new long[LAN.length][2];
        for (int i = 0; i < LAN.length; i++) {
            String[] p = LAN[i].split("/");
            String[] o = p[0].split("\\.");
            long a = (Long.parseLong(o[0]) << 24) | (Long.parseLong(o[1]) << 16) | (Long.parseLong(o[2]) << 8) | Long.parseLong(o[3]);
            int len = Integer.parseInt(p[1]);
            lan[i][0] = a;
            lan[i][1] = a + (1L << (32 - len)) - 1;
        }
        java.util.List<String> out = new ArrayList<>();
        split(0, 0, lan, out);
        return out;
    }

    private static void split(long start, int len, long[][] lan, java.util.List<String> out) {
        long end = start + (1L << (32 - len)) - 1;
        boolean overlaps = false;
        for (long[] r : lan) {
            if (r[0] <= start && end <= r[1]) return; // wholly local
            if (r[0] <= end && start <= r[1]) overlaps = true;
        }
        if (!overlaps) {
            out.add(((start >> 24) & 255) + "." + ((start >> 16) & 255) + "." + ((start >> 8) & 255) + "." + (start & 255) + "/" + len);
            return;
        }
        split(start, len + 1, lan, out);
        split(start + (1L << (31 - len)), len + 1, lan, out);
    }

    /** Another VPN took over, or the user switched this one off in the system. */
    @Override
    public void onRevoke() {
        gone();
    }

    private void gone() {
        prefs(this).edit().putBoolean("on", false).apply();
        core.send("stop");
        finish();
    }

    private void finish() {
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    @Override
    public void onDestroy() {
        if (instance == this) instance = null;
        core.unlisten(this);
        core.send("down");
        super.onDestroy();
    }

    @Override
    public void onCore(String ev, JSONObject o) {
        if (!ev.equals("status") && !ev.equals("state")) return;
        // nobody looks at a dark screen
        if (!getSystemService(PowerManager.class).isInteractive()) return;
        String before = shown;
        Notification n = note();
        if (shown.equals(before)) return;
        getSystemService(NotificationManager.class).notify(NOTE, n);
    }

    private PendingIntent open() {
        return PendingIntent.getActivity(this, 0, new Intent(this, Main.class), PendingIntent.FLAG_IMMUTABLE);
    }

    private boolean carrying() {
        JSONObject st = core.status;
        return st.optBoolean("up") && !st.optBoolean("standby");
    }

    private String title() {
        JSONObject st = core.status;
        if (st.optBoolean("up") && st.optBoolean("standby")) return getString(R.string.st_guard);
        JSONObject sv = core.server(st.optInt("server"));
        if (sv == null) return "BLACKWALL";
        // and where it really exits, when that is not what the provider says
        String exit = st.optString("exit");
        if (exit.length() != 2 || exit.equals(sv.optString("said"))) return sv.optString("name");
        String country;
        try {
            country = new Locale.Builder().setRegion(exit).build().getDisplayCountry();
        } catch (RuntimeException e) {
            country = exit;
        }
        return sv.optString("name") + " · " + (country.isEmpty() ? exit : country);
    }

    private String text() {
        if (!carrying()) return "";
        return "↓ " + Main.rate(core.rateDown) + "   ↑ " + Main.rate(core.rateUp);
    }

    /**
     * What fits beside the icon in the status bar chip (Android 16 "Live
     * Updates"): the download speed while something is moving. With nothing
     * to say the chip shows the time connected.
     */
    private String chip() {
        double bits = core.rateDown * 8;
        if (bits >= 1e7) return String.format(Locale.US, "↓%.0fM", bits / 1e6);
        if (bits >= 1e6) return String.format(Locale.US, "↓%.1fM", bits / 1e6);
        if (bits >= 1e5) return String.format(Locale.US, "↓%.0fK", bits / 1e3);
        return null;
    }

    /**
     * The panel in the notification shade: the server, how long it has been
     * connected (the system counts, nothing is redrawn for it), the speed,
     * and the switch. On Android 16 the same notification asks to be a Live
     * Update, which puts it into the status bar chip, the lock screen and
     * the always-on display.
     */
    private Notification note() {
        boolean carrying = carrying();
        String chip = carrying ? chip() : null;
        String text = text();
        shown = title() + "\n" + text + "\n" + chip;
        Notification.Builder b = new Notification.Builder(this, CHANNEL)
                .setSmallIcon(carrying ? R.drawable.ic_note : R.drawable.ic_note_off)
                .setContentTitle(title())
                .setContentText(text)
                .setContentIntent(open())
                .setCategory(Notification.CATEGORY_SERVICE)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .addAction(new Notification.Action.Builder(null,
                        getString(carrying ? R.string.disconnect : R.string.connect),
                        PendingIntent.getForegroundService(this, carrying ? 1 : 2,
                                new Intent(this, Tunnel.class).setAction(carrying ? OFF : ON),
                                PendingIntent.FLAG_IMMUTABLE)).build());
        if (carrying && core.upSince != 0) {
            b.setShowWhen(true).setUsesChronometer(true)
                    .setWhen(System.currentTimeMillis() - (SystemClock.elapsedRealtime() - core.upSince));
        } else {
            b.setShowWhen(false);
        }
        if (Build.VERSION.SDK_INT >= 36 && carrying) {
            Bundle live = new Bundle();
            live.putBoolean("android.requestPromotedOngoing", true);
            b.addExtras(live);
            if (chip != null) b.setShortCriticalText(chip);
        }
        return b.build();
    }
}
