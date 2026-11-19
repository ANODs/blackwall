package dev.blackwall;

import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.net.Uri;
import android.os.Build;
import android.provider.MediaStore;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.TreeMap;

/**
 * Settings → "Report for GitHub": what the app logged (its own logcat
 * lines) without secrets (src/core/diag.zig), saved to Downloads, and a new
 * issue to attach it to.
 */
final class Report {
    private static final String ISSUES = "https://github.com/ANODs/blackwall/issues/new";
    /** the latest lines; older ones rarely matter and only make the file long */
    private static final int MAX_LOG = 512 * 1024;

    private Report() {}

    /** Off the main thread: the saved file's name, or null. */
    static String save(Context c, JSONObject state) {
        Date now = new Date();
        String name = "BLACKWALL-report-" + new SimpleDateFormat("yyyy-MM-dd-HHmm", Locale.ROOT).format(now) + ".txt";
        StringBuilder sb = new StringBuilder();
        sb.append("BLACKWALL report, ").append(new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.ROOT).format(now)).append('\n');
        sb.append("version ").append(Core.version(c)).append(", ").append(system()).append('\n');
        summary(sb, state);
        sb.append("\n===== logcat\n").append(logcat());
        String text = Core.scrubbed(sb.toString());
        if (text == null) return null;
        ContentResolver r = c.getContentResolver();
        ContentValues v = new ContentValues();
        v.put(MediaStore.Downloads.DISPLAY_NAME, name);
        v.put(MediaStore.Downloads.MIME_TYPE, "text/plain");
        Uri uri = r.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, v);
        if (uri == null) return null;
        try (OutputStream o = r.openOutputStream(uri)) {
            if (o == null) return null;
            o.write(text.getBytes(StandardCharsets.UTF_8));
            return name;
        } catch (Exception e) {
            r.delete(uri, null, null);
            return null;
        }
    }

    /** A new issue on GitHub that says which file to attach. */
    static Uri issue(Context c, String name) {
        String body = c.getString(R.string.issue_what) + "\n\n\n\n"
                + c.getString(R.string.issue_attach) + " " + name + "\n\n"
                + "BLACKWALL " + Core.version(c) + ", " + system() + "\n";
        return Uri.parse(ISSUES).buildUpon()
                .appendQueryParameter("title", "")
                .appendQueryParameter("body", body)
                .build();
    }

    private static String system() {
        String abi = Build.SUPPORTED_ABIS.length > 0 ? Build.SUPPORTED_ABIS[0] : "?";
        return "Android " + Build.VERSION.RELEASE + " (API " + Build.VERSION.SDK_INT + "), " + Build.MANUFACTURER + " " + Build.MODEL + ", " + abi;
    }

    /** What the servers and rules are, never where they lead. */
    private static void summary(StringBuilder sb, JSONObject s) {
        if (s == null) return;
        JSONArray servers = s.optJSONArray("servers");
        TreeMap<String, Integer> protocols = new TreeMap<>();
        int usable = 0;
        String chosen = null;
        long selected = s.optLong("selected"), current = s.optLong("current");
        if (servers != null) for (int i = 0; i < servers.length(); i++) {
            JSONObject sv = servers.optJSONObject(i);
            if (sv == null) continue;
            String p = sv.optString("proto");
            protocols.merge(p, 1, Integer::sum);
            if (sv.optBoolean("ok")) usable++;
            if (sv.optLong("id") == (current != 0 ? current : selected)) chosen = p + ", " + sv.optString("cc");
        }
        JSONArray subs = s.optJSONArray("subs"), rules = s.optJSONArray("rules"), sites = s.optJSONArray("sites");
        sb.append("subscriptions ").append(subs == null ? 0 : subs.length())
                .append(", servers ").append(servers == null ? 0 : servers.length())
                .append(" (usable ").append(usable).append("):");
        for (java.util.Map.Entry<String, Integer> e : protocols.entrySet()) sb.append(' ').append(e.getKey()).append(' ').append(e.getValue());
        sb.append('\n');
        if (chosen != null) sb.append("chosen server: ").append(chosen).append('\n');
        sb.append("rules: ").append(rules == null ? 0 : rules.length()).append(" applications, ")
                .append(sites == null ? 0 : sites.length()).append(" sites\n");
        sb.append("settings: active=").append(s.optBoolean("active"))
                .append(" failover=").append(s.optBoolean("failover"))
                .append(" exitcheck=").append(s.optBoolean("exitcheck"))
                .append(" guard=").append(s.optBoolean("guard"))
                .append(" ipv6=").append(s.optString("ipv6"))
                .append(" direct=").append(s.optBoolean("direct"))
                .append(" standby=").append(s.optBoolean("standby")).append('\n');
    }

    /** This app's own lines in the system log (an app sees no other's). */
    private static String logcat() {
        try {
            Process p = new ProcessBuilder("logcat", "-d", "-v", "time", "-t", "4000").redirectErrorStream(true).start();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[16384];
            try (InputStream in = p.getInputStream()) {
                for (int n; (n = in.read(buf)) > 0; ) out.write(buf, 0, n);
            }
            p.waitFor();
            byte[] all = out.toByteArray();
            int from = Math.max(0, all.length - MAX_LOG);
            return new String(all, from, all.length - from, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "(logcat: " + e.getClass().getSimpleName() + ")\n";
        }
    }
}
