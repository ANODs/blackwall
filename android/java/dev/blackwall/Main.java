package dev.blackwall;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.SystemClock;
import android.provider.Settings;
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.widget.BaseAdapter;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.PopupMenu;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.text.Collator;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;

/**
 * The window: the switch, the applications, the servers, the settings.
 * It shows what the core reports and tells the core what the user chose;
 * it keeps no state of its own. Text is kept to names and numbers, the
 * explanations live in the settings.
 */
public class Main extends Activity implements Core.Listener {
    static final int BG = 0xFF0A0A0C, CARD = 0xFF16161A, LINE = 0xFF2A2A30, TEXT = 0xFFF2F2F2, DIM = 0xFF8E8E93,
            GREEN = 0xFF34C77B, AMBER = 0xFFE0A030, RED = 0xFFE5484D;
    private static final int CONNECT = 0, APPS = 1, SERVERS = 2, SETTINGS = 3;
    private static final String PRIVACY = "https://github.com/ANODs/blackwall/blob/main/docs/privacy.md";
    private static final int MATCH = ViewGroup.LayoutParams.MATCH_PARENT, WRAP = ViewGroup.LayoutParams.WRAP_CONTENT;

    private Core core;
    private FrameLayout content;
    private final ImageView[] tabs = new ImageView[4];
    private int screen = -1;
    private float density;

    private PowerButton power;
    private TextView timer, guard, serverCc, serverName, serverPing, down, up;
    private ServerAdapter servers;
    private AppAdapter apps;
    /** Installed applications, read once per process. */
    private static List<AppInfo> installed;

    // ------------------------------------------------------------ frame

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        density = getResources().getDisplayMetrics().density;
        core = Core.get(this);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(BG);
        content = new FrameLayout(this);
        root.addView(content, new LinearLayout.LayoutParams(MATCH, 0, 1));
        LinearLayout nav = new LinearLayout(this);
        int[] kinds = {Glyph.POWER, Glyph.APPS, Glyph.GLOBE, Glyph.SLIDERS};
        for (int i = 0; i < tabs.length; i++) {
            final int which = i;
            ImageView v = new ImageView(this);
            v.setScaleType(ImageView.ScaleType.CENTER);
            v.setTag(kinds[i]);
            v.setOnClickListener(x -> show(which));
            tabs[i] = v;
            nav.addView(v, new LinearLayout.LayoutParams(0, MATCH, 1));
        }
        root.addView(nav, new LinearLayout.LayoutParams(MATCH, dp(64)));

        // drawn edge to edge: the bars and the keyboard are padded for here
        if (Build.VERSION.SDK_INT >= 30) {
            getWindow().setDecorFitsSystemWindows(false);
            root.setOnApplyWindowInsetsListener((v, insets) -> {
                android.graphics.Insets s = insets.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.ime());
                v.setPadding(s.left, s.top, s.right, s.bottom);
                return insets;
            });
        }
        setContentView(root);
        show(saved == null ? CONNECT : saved.getInt("screen", CONNECT));
    }

    @Override
    protected void onSaveInstanceState(Bundle out) {
        super.onSaveInstanceState(out);
        out.putInt("screen", screen);
    }

    @Override
    protected void onStart() {
        super.onStart();
        core.listen(this);
        core.send("state");
        refresh();
    }

    @Override
    protected void onStop() {
        core.unlisten(this);
        super.onStop();
    }

    @Override
    public void onBackPressed() {
        if (screen != CONNECT) show(CONNECT);
        else super.onBackPressed();
    }

    private void show(int which) {
        if (which == screen) return;
        screen = which;
        for (int i = 0; i < tabs.length; i++) {
            tabs[i].setImageDrawable(glyph((Integer) tabs[i].getTag(), i == which ? TEXT : DIM, 26));
        }
        content.removeAllViews();
        power = null;
        servers = null;
        apps = null;
        switch (which) {
            case CONNECT:
                content.addView(connectScreen());
                break;
            case APPS:
                content.addView(appsScreen());
                break;
            case SERVERS:
                content.addView(serversScreen());
                break;
            case SETTINGS:
                content.addView(settingsScreen());
                break;
        }
        refresh();
    }

    @Override
    public void onCore(String ev, JSONObject o) {
        switch (ev) {
            case "state":
            case "status":
                if (ev.equals("status") && o.optBoolean("failed")) toast(getString(R.string.n_start));
                refresh();
                break;
            case "note":
                note(o);
                break;
        }
    }

    private void note(JSONObject o) {
        int n = o.optInt("n"), skipped = o.optInt("skipped");
        switch (o.optString("kind")) {
            case "added":
                toast(skipped > 0 ? getString(R.string.n_added_skipped, n, skipped) : getString(R.string.n_added, n));
                break;
            case "updated":
                toast(skipped > 0 ? getString(R.string.n_updated_skipped, n, skipped) : getString(R.string.n_updated, n));
                break;
            case "failed":
                toast(getString(R.string.n_failed));
                break;
            case "empty":
                toast(getString(R.string.n_empty));
                break;
        }
    }

    private void refresh() {
        if (power != null) refreshConnect();
        if (servers != null) servers.set(core.state);
        if (apps != null) apps.set(core.state);
    }

    // ------------------------------------------------------------ the switch

    private View connectScreen() {
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setGravity(Gravity.CENTER_HORIZONTAL);
        col.setPadding(dp(20), 0, dp(20), dp(8));

        col.addView(new View(this), new LinearLayout.LayoutParams(1, 0, 1));
        guard = label("", 14, DIM);
        guard.setGravity(Gravity.CENTER);
        col.addView(guard, new LinearLayout.LayoutParams(MATCH, dp(40)));
        power = new PowerButton(this);
        power.setOnClickListener(v -> toggle());
        col.addView(power, new LinearLayout.LayoutParams(dp(208), dp(208)));
        timer = label("", 16, DIM);
        timer.setTypeface(Typeface.MONOSPACE);
        timer.setGravity(Gravity.CENTER);
        col.addView(timer, new LinearLayout.LayoutParams(MATCH, dp(48)));

        LinearLayout chip = new LinearLayout(this);
        chip.setGravity(Gravity.CENTER_VERTICAL);
        chip.setPadding(dp(8), dp(8), dp(8), dp(8));
        chip.setOnClickListener(v -> show(SERVERS));
        serverCc = badge();
        chip.addView(serverCc);
        serverName = label("", 17, TEXT);
        serverName.setSingleLine();
        serverName.setEllipsize(TextUtils.TruncateAt.END);
        serverName.setMaxWidth(dp(190));
        chip.addView(serverName, margins(WRAP, WRAP, 12, 0, 10, 0));
        serverPing = label("", 14, DIM);
        chip.addView(serverPing);
        ImageView go = new ImageView(this);
        go.setImageDrawable(glyph(Glyph.CHEVRON, DIM, 18));
        chip.addView(go, margins(WRAP, WRAP, 6, 0, 0, 0));
        col.addView(chip, new LinearLayout.LayoutParams(WRAP, WRAP));
        col.addView(new View(this), new LinearLayout.LayoutParams(1, 0, 1));

        LinearLayout card = new LinearLayout(this);
        card.setBackground(round(CARD, 18));
        card.setPadding(dp(20), dp(18), dp(20), dp(18));
        down = rateCell(card, Glyph.DOWN);
        up = rateCell(card, Glyph.UP);
        col.addView(card, new LinearLayout.LayoutParams(MATCH, WRAP));
        return col;
    }

    private TextView rateCell(LinearLayout card, int kind) {
        LinearLayout cell = new LinearLayout(this);
        cell.setGravity(Gravity.CENTER_VERTICAL);
        ImageView arrow = new ImageView(this);
        arrow.setImageDrawable(glyph(kind, kind == Glyph.DOWN ? TEXT : DIM, 18));
        cell.addView(arrow);
        TextView value = label("", 17, TEXT);
        value.setTypeface(Typeface.MONOSPACE);
        cell.addView(value, margins(WRAP, WRAP, 10, 0, 0, 0));
        card.addView(cell, new LinearLayout.LayoutParams(0, WRAP, 1));
        return value;
    }

    private void refreshConnect() {
        JSONObject st = core.status, s = core.state;
        boolean tun = st.optBoolean("up"), held = tun && st.optBoolean("standby");
        boolean wanted = s.optBoolean("active") && !s.optBoolean("standby");
        int look = tun && !held ? PowerButton.ON : wanted ? PowerButton.BUSY : held ? PowerButton.GUARD : PowerButton.OFF;
        power.setLook(look);
        guard.setText(look == PowerButton.GUARD ? getString(R.string.st_guard) : "");

        long secs = core.upSince == 0 ? 0 : (SystemClock.elapsedRealtime() - core.upSince) / 1000;
        timer.setText(look == PowerButton.ON
                ? String.format(Locale.US, "%02d:%02d:%02d", secs / 3600, secs / 60 % 60, secs % 60) : "");

        // the server in use (a reserve one after a switch), else the one chosen
        JSONObject sv = core.server(look == PowerButton.ON ? st.optInt("server") : 0);
        if (sv == null) sv = core.server(s.optInt("current"));
        serverCc.setText(country(sv));
        serverName.setText(sv == null ? "" : sv.optString("name"));
        serverPing.setText(sv == null || sv.isNull("ping") ? "" : sv.optInt("ping") + " ms");
        down.setText(rate(look == PowerButton.ON ? core.rateDown : 0));
        up.setText(rate(look == PowerButton.ON ? core.rateUp : 0));
    }

    private void toggle() {
        JSONObject s = core.state;
        if (s.optBoolean("active") && !s.optBoolean("standby")) {
            Tunnel.prefs(this).edit().putBoolean("on", false).apply();
            core.send("disconnect");
            return;
        }
        JSONArray list = s.optJSONArray("servers");
        if (list == null || list.length() == 0) {
            show(SERVERS);
            addDialog();
            return;
        }
        // the system asks once whether this app may be a VPN
        Intent consent = VpnService.prepare(this);
        if (consent != null) startActivityForResult(consent, 1);
        else connect();
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        if (request == 1 && result == RESULT_OK) connect();
        if (request == 3 && result == RESULT_OK && data != null && data.getData() != null) {
            final android.net.Uri uri = data.getData();
            new Thread(() -> {
                final String text = Scanner.fromPicture(this, uri);
                runOnUiThread(() -> {
                    if (text == null) toast(getString(R.string.qr_none));
                    else scanned(text);
                });
            }, "qr").start();
        }
    }

    private void connect() {
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 2);
        }
        Tunnel.prefs(this).edit().putBoolean("on", true).apply();
        core.send("connect");
    }

    /** A server's country code; two dots when it is not known. */
    private static String country(JSONObject sv) {
        String cc = sv == null ? "" : sv.optString("cc");
        return cc.isEmpty() || cc.equals("??") ? "··" : cc;
    }

    static String rate(double bytesPerSecond) {
        double bits = bytesPerSecond * 8;
        if (bits >= 1e6) return String.format(Locale.US, "%.1f Mbit/s", bits / 1e6);
        return String.format(Locale.US, "%.0f kbit/s", bits / 1e3);
    }

    // ------------------------------------------------------------ servers

    private View serversScreen() {
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        LinearLayout bar = new LinearLayout(this);
        bar.setGravity(Gravity.END | Gravity.CENTER_VERTICAL);
        bar.setPadding(dp(8), 0, dp(8), 0);
        bar.addView(button(Glyph.REFRESH, DIM, v -> {
            core.send("refresh");
            core.send("ping");
        }));
        bar.addView(button(Glyph.PLUS, TEXT, v -> addDialog()));
        col.addView(bar, new LinearLayout.LayoutParams(MATCH, dp(56)));
        ListView list = list();
        servers = new ServerAdapter();
        list.setAdapter(servers);
        col.addView(list, new LinearLayout.LayoutParams(MATCH, 0, 1));
        return col;
    }

    private void addDialog() {
        final EditText in = new EditText(this);
        in.setHint(R.string.add_hint);
        in.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE
                | android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS | android.text.InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD);
        in.setMinLines(3);
        in.setMaxLines(8);
        in.setTextSize(15);
        in.setGravity(Gravity.TOP);
        // what was just copied, when it is what this field takes
        ClipData clip = getSystemService(ClipboardManager.class).getPrimaryClip();
        if (clip != null && clip.getItemCount() > 0 && clip.getItemAt(0).getText() != null) {
            String text = clip.getItemAt(0).getText().toString().trim();
            if (text.matches("(?is)^(https?|vless|vmess|trojan|ss|hysteria2|hy2|tuic|wireguard|wg)://.*")) in.setText(text);
        }
        FrameLayout box = new FrameLayout(this);
        box.setPadding(dp(20), dp(12), dp(20), 0);
        box.addView(in);
        new AlertDialog.Builder(this)
                .setView(box)
                .setPositiveButton(R.string.add, (dlg, w) -> core.send("add", "text", in.getText().toString()))
                .setNegativeButton(R.string.cancel, null)
                .setNeutralButton(R.string.qr, (dlg, w) -> qrChoice())
                .show();
    }

    // ------------------------------------------------------------ QR codes

    private void qrChoice() {
        String[] items = {getString(R.string.qr_camera), getString(R.string.qr_picture)};
        new AlertDialog.Builder(this)
                .setTitle(R.string.qr)
                .setItems(items, (d, which) -> {
                    if (which == 0) camera();
                    else startActivityForResult(new Intent(Intent.ACTION_GET_CONTENT).setType("image/*").addCategory(Intent.CATEGORY_OPENABLE), 3);
                })
                .show();
    }

    private void camera() {
        if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.CAMERA}, 4);
            return;
        }
        new Scanner(this, this::scanned).show();
    }

    @Override
    public void onRequestPermissionsResult(int request, String[] permissions, int[] results) {
        if (request == 4 && results.length > 0 && results[0] == PackageManager.PERMISSION_GRANTED) camera();
    }

    /** What a scan found: added as it is. */
    private void scanned(String text) {
        if (text == null) return;
        core.send("add", "text", text);
    }

    private final class ServerAdapter extends BaseAdapter {
        /** null: "Fastest"; has "proto": a server; otherwise a subscription. */
        private final ArrayList<JSONObject> rows = new ArrayList<>();
        private int selected;

        void set(JSONObject state) {
            rows.clear();
            rows.add(null);
            selected = state.optInt("selected");
            JSONArray subs = state.optJSONArray("subs"), list = state.optJSONArray("servers");
            for (int i = 0; subs != null && i < subs.length(); i++) {
                JSONObject sub = subs.optJSONObject(i);
                rows.add(sub);
                for (int k = 0; list != null && k < list.length(); k++) {
                    JSONObject sv = list.optJSONObject(k);
                    if (sv.optInt("sub") == sub.optInt("id")) rows.add(sv);
                }
            }
            notifyDataSetChanged();
        }

        @Override
        public int getCount() {
            return rows.size();
        }

        @Override
        public Object getItem(int i) {
            return rows.get(i);
        }

        @Override
        public long getItemId(int i) {
            return i;
        }

        @Override
        public int getViewTypeCount() {
            return 2;
        }

        @Override
        public int getItemViewType(int i) {
            JSONObject o = rows.get(i);
            return o != null && !o.has("proto") ? 1 : 0;
        }

        @Override
        public View getView(int i, View old, ViewGroup parent) {
            final JSONObject o = rows.get(i);
            if (getItemViewType(i) == 1) return header(o, old);
            Holder h;
            if (old == null) {
                h = new Holder();
                LinearLayout row = row();
                h.cc = badge();
                row.addView(h.cc);
                LinearLayout names = new LinearLayout(Main.this);
                names.setOrientation(LinearLayout.VERTICAL);
                h.name = label("", 16, TEXT);
                h.name.setSingleLine();
                h.name.setEllipsize(TextUtils.TruncateAt.END);
                names.addView(h.name);
                h.proto = label("", 12, DIM);
                names.addView(h.proto);
                row.addView(names, margins(0, WRAP, 14, 0, 8, 0, 1));
                h.ping = label("", 14, DIM);
                h.ping.setTypeface(Typeface.MONOSPACE);
                row.addView(h.ping);
                h.check = new ImageView(Main.this);
                h.check.setImageDrawable(glyph(Glyph.CHECK, TEXT, 20));
                row.addView(h.check, margins(WRAP, WRAP, 10, 0, 0, 0));
                h.star = new ImageView(Main.this);
                h.star.setPadding(dp(12), dp(12), dp(4), dp(12));
                row.addView(h.star);
                row.setTag(h);
                old = row;
            }
            h = (Holder) old.getTag();
            if (o == null) {
                h.cc.setText("");
                h.cc.setCompoundDrawablesWithIntrinsicBounds(glyph(Glyph.BOLT, TEXT, 16), null, null, null);
                h.cc.setPadding(dp(10), 0, 0, 0);
                h.name.setText(R.string.fastest);
                h.name.setAlpha(1);
                h.proto.setVisibility(View.GONE);
                h.ping.setText("");
                h.star.setVisibility(View.INVISIBLE);
                h.check.setVisibility(selected == 0 ? View.VISIBLE : View.GONE);
                old.setOnClickListener(v -> core.send("select", "id", 0));
                return old;
            }
            final int id = o.optInt("id");
            h.cc.setCompoundDrawables(null, null, null, null);
            h.cc.setPadding(0, 0, 0, 0);
            h.cc.setText(country(o));
            h.name.setText(o.optString("name"));
            h.name.setAlpha(o.optBoolean("ok") ? 1f : 0.4f);
            h.proto.setVisibility(View.VISIBLE);
            h.proto.setText(o.optString("proto"));
            if (o.isNull("ping")) {
                h.ping.setText(o.optBoolean("pinging") ? "···" : "—");
                h.ping.setTextColor(DIM);
            } else {
                int ms = o.optInt("ping");
                h.ping.setText(ms + " ms");
                h.ping.setTextColor(ms < 100 ? GREEN : ms < 200 ? AMBER : RED);
            }
            h.check.setVisibility(selected == id ? View.VISIBLE : View.GONE);
            h.star.setVisibility(View.VISIBLE);
            boolean star = o.optBoolean("star");
            h.star.setImageDrawable(glyph(star ? Glyph.STAR_ON : Glyph.STAR, star ? TEXT : LINE, 20));
            h.star.setOnClickListener(v -> core.send("star", "id", id));
            old.setOnClickListener(v -> core.send("select", "id", id));
            return old;
        }

        private View header(final JSONObject sub, View old) {
            LinearLayout row;
            if (old == null) {
                row = new LinearLayout(Main.this);
                row.setGravity(Gravity.CENTER_VERTICAL);
                row.setPadding(dp(20), dp(14), dp(8), 0);
                TextView name = label("", 13, DIM);
                row.addView(name, new LinearLayout.LayoutParams(0, WRAP, 1));
                ImageView trash = new ImageView(Main.this);
                trash.setImageDrawable(glyph(Glyph.TRASH, DIM, 18));
                trash.setPadding(dp(12), dp(8), dp(12), dp(8));
                row.addView(trash);
            } else {
                row = (LinearLayout) old;
            }
            final String name = sub.optString("name").isEmpty() ? getString(R.string.keys) : sub.optString("name");
            TextView text = (TextView) row.getChildAt(0);
            text.setText(name);
            text.setTextColor(sub.optBoolean("failed") ? RED : DIM);
            row.getChildAt(1).setOnClickListener(v -> new AlertDialog.Builder(Main.this)
                    .setMessage(getString(R.string.remove_q, name))
                    .setPositiveButton(R.string.remove, (dlg, w) -> core.send("remove", "id", sub.optInt("id")))
                    .setNegativeButton(R.string.cancel, null)
                    .show());
            return row;
        }
    }

    private static final class Holder {
        TextView cc, name, proto, ping;
        ImageView check, star, icon;
    }

    // ------------------------------------------------------------ applications

    private static final class AppInfo {
        String pkg, name;
        Drawable icon;
    }

    private View appsScreen() {
        ListView list = list();
        apps = new AppAdapter();
        list.setAdapter(apps);
        if (installed == null) {
            new Thread(() -> {
                final List<AppInfo> found = readApps();
                runOnUiThread(() -> {
                    installed = found;
                    if (apps != null) apps.set(core.state);
                });
            }, "apps").start();
        }
        return list;
    }

    private List<AppInfo> readApps() {
        PackageManager pm = getPackageManager();
        Intent launch = new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER);
        ArrayList<AppInfo> found = new ArrayList<>();
        HashSet<String> seen = new HashSet<>();
        seen.add(getPackageName());
        for (ResolveInfo r : pm.queryIntentActivities(launch, 0)) {
            if (!seen.add(r.activityInfo.packageName)) continue;
            AppInfo a = new AppInfo();
            a.pkg = r.activityInfo.packageName;
            a.name = String.valueOf(r.activityInfo.applicationInfo.loadLabel(pm));
            a.icon = r.activityInfo.applicationInfo.loadIcon(pm);
            found.add(a);
        }
        final Collator order = Collator.getInstance();
        found.sort((x, y) -> order.compare(x.name, y.name));
        return found;
    }

    private final class AppAdapter extends BaseAdapter {
        private final ArrayList<AppInfo> rows = new ArrayList<>();
        private final HashMap<String, String> routes = new HashMap<>();
        /** sites with their routes, in the order they were added */
        private final ArrayList<String[]> sites = new ArrayList<>();
        private boolean direct;

        void set(JSONObject state) {
            sites.clear();
            JSONArray ss = state.optJSONArray("sites");
            for (int i = 0; ss != null && i < ss.length(); i++) {
                JSONObject o = ss.optJSONObject(i);
                sites.add(new String[]{o.optString("name"), o.optString("route")});
            }
            routes.clear();
            JSONArray rules = state.optJSONArray("rules");
            for (int i = 0; rules != null && i < rules.length(); i++) {
                JSONObject r = rules.optJSONObject(i);
                routes.put(r.optString("app"), r.optString("route"));
            }
            direct = state.optBoolean("direct");
            // applications with a rule of their own come first
            rows.clear();
            if (installed != null) {
                for (AppInfo a : installed) if (routes.containsKey(a.pkg)) rows.add(a);
                for (AppInfo a : installed) if (!routes.containsKey(a.pkg)) rows.add(a);
            }
            notifyDataSetChanged();
        }

        /** Rows: all others, adding a site, the sites, then the applications. */
        @Override
        public int getCount() {
            return 2 + sites.size() + rows.size();
        }

        @Override
        public Object getItem(int i) {
            return i < 2 + sites.size() ? null : rows.get(i - 2 - sites.size());
        }

        @Override
        public long getItemId(int i) {
            return i;
        }

        @Override
        public View getView(int i, View old, ViewGroup parent) {
            Holder h;
            if (old == null) {
                h = new Holder();
                LinearLayout row = row();
                h.icon = new ImageView(Main.this);
                row.addView(h.icon, new LinearLayout.LayoutParams(dp(40), dp(40)));
                h.name = label("", 16, TEXT);
                h.name.setSingleLine();
                h.name.setEllipsize(TextUtils.TruncateAt.END);
                row.addView(h.name, margins(0, WRAP, 14, 0, 8, 0, 1));
                h.star = new ImageView(Main.this);
                row.addView(h.star, margins(WRAP, WRAP, 0, 0, 8, 0));
                row.setTag(h);
                old = row;
            }
            h = (Holder) old.getTag();
            if (i == 0) {
                h.icon.setImageDrawable(glyph(Glyph.APPS, DIM, 24));
                h.icon.setScaleType(ImageView.ScaleType.CENTER);
                h.name.setText(R.string.others);
                h.star.setImageDrawable(glyph(direct ? Glyph.DIRECT : Glyph.GLOBE, TEXT, 20));
                old.setOnClickListener(v -> {
                    PopupMenu m = new PopupMenu(Main.this, v, Gravity.END);
                    m.getMenu().add(0, 0, 0, R.string.d_vpn);
                    m.getMenu().add(0, 1, 1, R.string.r_direct);
                    m.setOnMenuItemClickListener(it -> {
                        core.send("set", "key", "default", "value", it.getItemId() == 1 ? "direct" : "vpn");
                        return true;
                    });
                    m.show();
                });
                return old;
            }
            if (i == 1) {
                h.icon.setImageDrawable(glyph(Glyph.PLUS, DIM, 22));
                h.icon.setScaleType(ImageView.ScaleType.CENTER);
                h.name.setText(R.string.add_site);
                h.star.setImageDrawable(null);
                old.setOnClickListener(v -> siteDialog());
                return old;
            }
            if (i < 2 + sites.size()) {
                final String[] site = sites.get(i - 2);
                h.icon.setImageDrawable(glyph(Glyph.GLOBE, DIM, 22));
                h.icon.setScaleType(ImageView.ScaleType.CENTER);
                h.name.setText(site[0]);
                h.star.setImageDrawable(routeGlyph(site[1].equals("default") ? null : site[1]));
                old.setOnClickListener(v -> routeMenu(v, true, (route) -> {
                    if (route == null) core.send("unsite", "name", site[0]);
                    else core.send("site", "name", site[0], "route", route);
                }));
                return old;
            }
            final AppInfo a = rows.get(i - 2 - sites.size());
            h.icon.setScaleType(ImageView.ScaleType.FIT_CENTER);
            h.icon.setImageDrawable(a.icon);
            h.name.setText(a.name);
            h.star.setImageDrawable(routeGlyph(routes.get(a.pkg)));
            old.setOnClickListener(v -> routeMenu(v, false, (route) -> core.send("rule", "app", a.pkg, "name", a.name, "route", route)));
            return old;
        }
    }

    private interface Picked {
        /** null: remove (sites only) */
        void route(String route);
    }

    private Drawable routeGlyph(String route) {
        if (route == null) return glyph(Glyph.DOT, LINE, 20);
        if (route.equals("direct")) return glyph(Glyph.DIRECT, TEXT, 20);
        if (route.equals("dpi")) return glyph(Glyph.BOLT, TEXT, 20);
        if (route.equals("block")) return glyph(Glyph.BLOCK, RED, 20);
        return glyph(Glyph.GLOBE, TEXT, 20);
    }

    private void routeMenu(View anchor, boolean removable, final Picked picked) {
        final String[] names = {"default", "vpn", "direct", "dpi", "block"};
        int[] labels = {R.string.r_default, R.string.r_vpn, R.string.r_direct, R.string.r_dpi, R.string.r_block};
        PopupMenu m = new PopupMenu(this, anchor, Gravity.END);
        for (int k = 0; k < names.length; k++) m.getMenu().add(0, k, k, labels[k]);
        if (removable) m.getMenu().add(0, names.length, names.length, R.string.remove);
        m.setOnMenuItemClickListener(it -> {
            int k = it.getItemId();
            picked.route(k < names.length ? names[k] : null);
            return true;
        });
        m.show();
    }

    private void siteDialog() {
        final EditText in = new EditText(this);
        in.setHint(R.string.site_hint);
        in.setSingleLine();
        in.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_VARIATION_URI);
        FrameLayout box = new FrameLayout(this);
        box.setPadding(dp(20), dp(12), dp(20), 0);
        box.addView(in);
        new AlertDialog.Builder(this)
                .setTitle(R.string.add_site)
                .setView(box)
                .setPositiveButton(R.string.add, (dlg, w) -> core.send("site", "name", in.getText().toString().trim(), "route", "vpn"))
                .setNegativeButton(R.string.cancel, null)
                .show();
    }

    // ------------------------------------------------------------ settings

    private View settingsScreen() {
        JSONObject s = core.state;
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(dp(20), dp(16), dp(20), dp(16));

        col.addView(toggle(R.string.s_failover, R.string.s_failover_d, s.optBoolean("failover", true), "failover"));
        col.addView(toggle(R.string.s_guard, R.string.s_guard_d, s.optBoolean("guard", true), "guard"));

        final String[] modes = {"block", "tunnel", "system"};
        final int[] labels = {R.string.ipv6_block, R.string.ipv6_tunnel, R.string.ipv6_system};
        final TextView mode = label("", 15, TEXT);
        String now = s.optString("ipv6", "block");
        for (int i = 0; i < modes.length; i++) if (modes[i].equals(now)) mode.setText(labels[i]);
        View ipv6 = setting(R.string.s_ipv6, R.string.s_ipv6_d, mode);
        ipv6.setOnClickListener(v -> {
            PopupMenu m = new PopupMenu(this, mode, Gravity.END);
            for (int i = 0; i < modes.length; i++) m.getMenu().add(0, i, i, labels[i]);
            m.setOnMenuItemClickListener(it -> {
                mode.setText(labels[it.getItemId()]);
                core.send("set", "key", "ipv6", "value", modes[it.getItemId()]);
                return true;
            });
            m.show();
        });
        col.addView(ipv6);

        ImageView go = new ImageView(this);
        go.setImageDrawable(glyph(Glyph.CHEVRON, DIM, 18));
        View always = setting(R.string.s_always, R.string.s_always_d, go);
        always.setOnClickListener(v -> {
            try {
                startActivity(new Intent(Settings.ACTION_VPN_SETTINGS));
            } catch (Exception e) {
                // a system without that screen
            }
        });
        col.addView(always);

        ImageView send = new ImageView(this);
        send.setImageDrawable(glyph(Glyph.CHEVRON, DIM, 18));
        View report = setting(R.string.s_report, R.string.s_report_d, send);
        report.setOnClickListener(v -> {
            final JSONObject state = core.state;
            new Thread(() -> {
                final String name = Report.save(this, state);
                runOnUiThread(() -> {
                    if (name == null) {
                        toast(getString(R.string.report_failed));
                        return;
                    }
                    toast(getString(R.string.report_saved, name));
                    try {
                        startActivity(new Intent(Intent.ACTION_VIEW, Report.issue(this, name)));
                    } catch (Exception e) {
                        // no browser
                    }
                });
            }).start();
        });
        col.addView(report);

        // Google Play asks for the policy to be reachable from inside the app
        ImageView open = new ImageView(this);
        open.setImageDrawable(glyph(Glyph.CHEVRON, DIM, 18));
        View privacy = setting(R.string.s_privacy, R.string.s_privacy_d, open);
        privacy.setOnClickListener(v -> {
            try {
                startActivity(new Intent(Intent.ACTION_VIEW, android.net.Uri.parse(PRIVACY)));
            } catch (Exception e) {
                // no browser
            }
        });
        col.addView(privacy);

        TextView version = label("BLACKWALL " + Core.version(this), 12, DIM);
        version.setPadding(0, dp(24), 0, 0);
        col.addView(version);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(col);
        return scroll;
    }

    private View toggle(int title, int text, boolean on, final String key) {
        Switch sw = new Switch(this);
        sw.setChecked(on);
        sw.setOnCheckedChangeListener((b, checked) -> core.send("set", "key", key, "on", checked));
        View row = setting(title, text, sw);
        row.setOnClickListener(v -> sw.toggle());
        return row;
    }

    private View setting(int title, int text, View control) {
        LinearLayout row = new LinearLayout(this);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(0, dp(14), 0, dp(14));
        LinearLayout words = new LinearLayout(this);
        words.setOrientation(LinearLayout.VERTICAL);
        words.addView(label(getString(title), 16, TEXT));
        TextView more = label(getString(text), 13, DIM);
        more.setPadding(0, dp(4), 0, 0);
        words.addView(more);
        row.addView(words, margins(0, WRAP, 0, 0, 16, 0, 1));
        row.addView(control);
        return row;
    }

    // ------------------------------------------------------------ pieces

    private int dp(float v) {
        return Math.round(v * density);
    }

    private TextView label(String text, int sp, int color) {
        TextView t = new TextView(this);
        t.setText(text);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        t.setTextColor(color);
        return t;
    }

    /** The two letters of a country in a rounded box. */
    private TextView badge() {
        TextView t = label("", 12, TEXT);
        t.setTypeface(Typeface.MONOSPACE);
        t.setGravity(Gravity.CENTER);
        t.setBackground(round(CARD, 8));
        t.setLayoutParams(new LinearLayout.LayoutParams(dp(36), dp(28)));
        return t;
    }

    private Drawable glyph(int kind, int color, int sizeDp) {
        Glyph g = new Glyph(kind, color);
        g.setBounds(0, 0, dp(sizeDp), dp(sizeDp));
        return new android.graphics.drawable.InsetDrawable(g, 0) {
            @Override
            public int getIntrinsicWidth() {
                return dp(sizeDp);
            }

            @Override
            public int getIntrinsicHeight() {
                return dp(sizeDp);
            }
        };
    }

    private ImageView button(int kind, int color, View.OnClickListener click) {
        ImageView v = new ImageView(this);
        v.setImageDrawable(glyph(kind, color, 22));
        v.setScaleType(ImageView.ScaleType.CENTER);
        v.setOnClickListener(click);
        v.setLayoutParams(new LinearLayout.LayoutParams(dp(48), dp(48)));
        return v;
    }

    private GradientDrawable round(int color, int radiusDp) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(color);
        g.setCornerRadius(dp(radiusDp));
        return g;
    }

    private LinearLayout row() {
        LinearLayout row = new LinearLayout(this);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(dp(20), dp(10), dp(12), dp(10));
        row.setMinimumHeight(dp(60));
        return row;
    }

    private ListView list() {
        ListView list = new ListView(this);
        list.setDivider(null);
        list.setSelector(new android.graphics.drawable.ColorDrawable(0));
        list.setVerticalScrollBarEnabled(false);
        return list;
    }

    private LinearLayout.LayoutParams margins(int w, int h, int l, int t, int r, int b) {
        return margins(w, h, l, t, r, b, 0);
    }

    private LinearLayout.LayoutParams margins(int w, int h, int l, int t, int r, int b, float weight) {
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(w, h, weight);
        p.setMargins(dp(l), dp(t), dp(r), dp(b));
        return p;
    }

    private void toast(String text) {
        Toast.makeText(this, text, Toast.LENGTH_SHORT).show();
    }
}
