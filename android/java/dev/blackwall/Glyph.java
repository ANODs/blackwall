package dev.blackwall;

import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PixelFormat;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;

/** The interface's pictures, drawn as lines on a 24-unit square. */
final class Glyph extends Drawable {
    static final int POWER = 0, APPS = 1, GLOBE = 2, SLIDERS = 3, PLUS = 4, REFRESH = 5, STAR = 6, STAR_ON = 7,
            CHECK = 8, TRASH = 9, CHEVRON = 10, DOWN = 11, UP = 12, DIRECT = 13, BLOCK = 14, BOLT = 15, DOT = 16;

    private final int kind;
    private final Paint p = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Path path = new Path();
    private final RectF r = new RectF();

    Glyph(int kind, int color) {
        this.kind = kind;
        p.setColor(color);
        p.setStrokeWidth(1.8f);
        p.setStrokeCap(Paint.Cap.ROUND);
        p.setStrokeJoin(Paint.Join.ROUND);
    }

    @Override
    public void draw(Canvas c) {
        float size = Math.min(getBounds().width(), getBounds().height());
        c.save();
        c.translate(getBounds().left + (getBounds().width() - size) / 2f, getBounds().top + (getBounds().height() - size) / 2f);
        c.scale(size / 24f, size / 24f);
        p.setStyle(Paint.Style.STROKE);
        path.rewind();
        switch (kind) {
            case POWER:
                r.set(5, 6, 19, 20);
                c.drawArc(r, -55, 290, false, p);
                c.drawLine(12, 3.5f, 12, 11.5f, p);
                break;
            case APPS:
                for (int i = 0; i < 4; i++) {
                    float x = 4.5f + (i % 2) * 8.5f, y = 4.5f + (i / 2) * 8.5f;
                    r.set(x, y, x + 6.5f, y + 6.5f);
                    c.drawRoundRect(r, 1.6f, 1.6f, p);
                }
                break;
            case GLOBE:
                c.drawCircle(12, 12, 8.2f, p);
                r.set(8.3f, 3.8f, 15.7f, 20.2f);
                c.drawOval(r, p);
                c.drawLine(3.8f, 12, 20.2f, 12, p);
                break;
            case SLIDERS:
                c.drawLine(4, 8, 20, 8, p);
                c.drawLine(4, 16, 20, 16, p);
                p.setStyle(Paint.Style.FILL);
                c.drawCircle(9, 8, 2.6f, p);
                c.drawCircle(15, 16, 2.6f, p);
                break;
            case PLUS:
                c.drawLine(12, 5, 12, 19, p);
                c.drawLine(5, 12, 19, 12, p);
                break;
            case REFRESH:
                r.set(5, 5, 19, 19);
                c.drawArc(r, -20, -290, false, p);
                path.moveTo(18.6f, 4.6f);
                path.lineTo(18.6f, 9.6f);
                path.lineTo(13.6f, 9.6f);
                c.drawPath(path, p);
                break;
            case STAR:
            case STAR_ON:
                for (int i = 0; i < 10; i++) {
                    double a = -Math.PI / 2 + i * Math.PI / 5;
                    float rad = i % 2 == 0 ? 8.2f : 3.6f;
                    float x = 12 + (float) Math.cos(a) * rad, y = 12.6f + (float) Math.sin(a) * rad;
                    if (i == 0) path.moveTo(x, y);
                    else path.lineTo(x, y);
                }
                path.close();
                if (kind == STAR_ON) p.setStyle(Paint.Style.FILL_AND_STROKE);
                c.drawPath(path, p);
                break;
            case CHECK:
                path.moveTo(5, 12.5f);
                path.lineTo(10, 17.5f);
                path.lineTo(19, 7);
                c.drawPath(path, p);
                break;
            case TRASH:
                c.drawLine(5, 7, 19, 7, p);
                c.drawLine(10, 4.5f, 14, 4.5f, p);
                path.moveTo(7, 7);
                path.lineTo(8, 19.5f);
                path.lineTo(16, 19.5f);
                path.lineTo(17, 7);
                c.drawPath(path, p);
                break;
            case CHEVRON:
                path.moveTo(9, 6);
                path.lineTo(15, 12);
                path.lineTo(9, 18);
                c.drawPath(path, p);
                break;
            case DOWN:
            case UP:
                if (kind == UP) c.rotate(180, 12, 12);
                c.drawLine(12, 5, 12, 19, p);
                path.moveTo(6, 13);
                path.lineTo(12, 19);
                path.lineTo(18, 13);
                c.drawPath(path, p);
                break;
            case DIRECT:
                c.drawLine(4, 12, 20, 12, p);
                path.moveTo(14, 6);
                path.lineTo(20, 12);
                path.lineTo(14, 18);
                c.drawPath(path, p);
                break;
            case BLOCK:
                c.drawCircle(12, 12, 8.2f, p);
                c.drawLine(6.2f, 6.2f, 17.8f, 17.8f, p);
                break;
            case BOLT:
                path.moveTo(13.5f, 3);
                path.lineTo(6, 13.5f);
                path.lineTo(11.5f, 13.5f);
                path.lineTo(10.5f, 21);
                path.lineTo(18, 10.5f);
                path.lineTo(12.5f, 10.5f);
                path.close();
                p.setStyle(Paint.Style.FILL_AND_STROKE);
                p.setStrokeWidth(0.8f);
                c.drawPath(path, p);
                p.setStrokeWidth(1.8f);
                break;
            case DOT:
                p.setStyle(Paint.Style.FILL);
                c.drawCircle(12, 12, 2.2f, p);
                break;
        }
        c.restore();
    }

    @Override
    public void setAlpha(int alpha) {
        p.setAlpha(alpha);
    }

    @Override
    public void setColorFilter(ColorFilter cf) {
        p.setColorFilter(cf);
    }

    @Override
    public int getOpacity() {
        return PixelFormat.TRANSLUCENT;
    }
}
