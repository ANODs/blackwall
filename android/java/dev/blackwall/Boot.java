package dev.blackwall;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/**
 * After a restart of the device or an update of the app nothing of it runs.
 * Waking the core is enough: it brings back what was up (Core.restore).
 */
public class Boot extends BroadcastReceiver {
    @Override
    public void onReceive(Context c, Intent intent) {
        Core.get(c);
    }
}
