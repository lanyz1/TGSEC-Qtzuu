package org.lsposed.lspromise;

import android.app.AppComponentFactory;

public class MyAppComponentFactory extends AppComponentFactory {
    static {
        Shellcode.onAppComponentFactoryLoaded();
    }
}
