package network.geodema.misetanibox;

import android.graphics.Color;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.view.Window;
import android.webkit.WebView;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    private String insetsJs = "";

    @Override
    public void onCreate(Bundle savedInstanceState) {
        registerPlugin(VpnPlugin.class);
        super.onCreate(savedInstanceState);
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission("android.permission.POST_NOTIFICATIONS") != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, 41);
        }

        // edge-to-edge: обложка едет под статус-бар и панель жестов; WebView сам инсеты
        // системных панелей не отдаёт (env(safe-area-*) только для выреза) → шлём в CSS
        Window w = getWindow();
        WindowCompat.setDecorFitsSystemWindows(w, false);
        w.setStatusBarColor(Color.TRANSPARENT);
        w.setNavigationBarColor(Color.TRANSPARENT);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) w.setNavigationBarContrastEnforced(false);
        WindowCompat.getInsetsController(w, w.getDecorView()).setAppearanceLightStatusBars(false);
        WindowCompat.getInsetsController(w, w.getDecorView()).setAppearanceLightNavigationBars(false);

        final WebView wv = getBridge().getWebView();
        final float d = getResources().getDisplayMetrics().density;
        ViewCompat.setOnApplyWindowInsetsListener(wv, (v, insets) -> {
            Insets sb = insets.getInsets(WindowInsetsCompat.Type.systemBars() | WindowInsetsCompat.Type.displayCutout());
            // клавиатура: без decorFitsSystemWindows WebView сам не ужимается → паддинг на высоту IME
            int ime = insets.getInsets(WindowInsetsCompat.Type.ime()).bottom;
            v.setPadding(0, 0, 0, Math.max(0, ime - sb.bottom));
            insetsJs = "document.documentElement.style.setProperty('--sat','" + (int) (sb.top / d) + "px');"
                     + "document.documentElement.style.setProperty('--sab','" + (int) (sb.bottom / d) + "px');";
            wv.evaluateJavascript(insetsJs, null);
            return WindowInsetsCompat.CONSUMED;
        });
        // страница может загрузиться позже первого onApplyWindowInsets — повторим
        wv.postDelayed(() -> { if (!insetsJs.isEmpty()) wv.evaluateJavascript(insetsJs, null); }, 1500);
        wv.postDelayed(() -> { if (!insetsJs.isEmpty()) wv.evaluateJavascript(insetsJs, null); }, 4000);
    }

    // системная «назад»: страницу/лист закрывает JS; 'exit' — сворачиваем
    @Override
    public void onBackPressed() {
        WebView wv = getBridge().getWebView();
        if (wv == null) { super.onBackPressed(); return; }
        wv.evaluateJavascript("(typeof navBack==='function')?navBack():'exit'", v -> {
            if (v == null || v.contains("exit")) moveTaskToBack(true);
        });
    }
}
