package dev.blackwall;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.os.SystemClock;
import android.view.View;

/** The switch: a disc in a ring. Light when the VPN carries traffic. */
final class PowerButton extends View {
    static final int OFF = 0, BUSY = 1, ON = 2, GUARD = 3;

    private int look = OFF;
    private final Paint p = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final RectF r = new RectF();
    private final Glyph dark = new Glyph(Glyph.POWER, Main.BG), light = new Glyph(Glyph.POWER, Main.TEXT);

    PowerButton(Context c) {
        super(c);
        setClickable(true);
    }

    void setLook(int l) {
        if (l == look) return;
        look = l;
        invalidate();
    }

    @Override
    protected void onDraw(Canvas c) {
        float w = getWidth(), h = getHeight(), cx = w / 2, cy = h / 2;
        float outer = Math.min(w, h) / 2 - 2, stroke = outer * 0.035f;
        float disc = outer * 0.80f * (isPressed() ? 0.97f : 1f);

        p.setStyle(Paint.Style.STROKE);
        p.setStrokeWidth(look == GUARD ? stroke * 1.6f : stroke);
        p.setColor(look == ON || look == GUARD ? Main.TEXT : Main.LINE);
        if (look == BUSY) {
            // a quarter of the ring going round
            c.drawCircle(cx, cy, outer, p);
            p.setColor(Main.TEXT);
            p.setStrokeCap(Paint.Cap.ROUND);
            r.set(cx - outer, cy - outer, cx + outer, cy + outer);
            c.drawArc(r, (SystemClock.uptimeMillis() % 1200) * 0.3f, 80, false, p);
            postInvalidateOnAnimation();
        } else {
            c.drawCircle(cx, cy, outer, p);
        }

        p.setStyle(Paint.Style.FILL);
        p.setColor(look == ON ? Main.TEXT : Main.CARD);
        c.drawCircle(cx, cy, disc, p);

        Glyph g = look == ON ? dark : light;
        int s = (int) (disc * 0.62f);
        g.setBounds((int) cx - s / 2, (int) cy - s / 2, (int) cx + s / 2, (int) cy + s / 2);
        g.setAlpha(look == OFF || look == BUSY ? 150 : 255);
        g.draw(c);
    }

    @Override
    protected void drawableStateChanged() {
        super.drawableStateChanged();
        invalidate();
    }
}
