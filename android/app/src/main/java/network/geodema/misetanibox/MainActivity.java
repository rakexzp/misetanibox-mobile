package network.geodema.misetanibox;

import android.os.Bundle;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        registerPlugin(VpnPlugin.class);
        super.onCreate(savedInstanceState);
    }
}
