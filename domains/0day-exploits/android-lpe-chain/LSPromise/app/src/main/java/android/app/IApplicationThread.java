package android.app;

import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.res.CompatibilityInfo;
import android.os.Bundle;

public interface IApplicationThread {
    void scheduleReceiver(Intent intent, ActivityInfo info, CompatibilityInfo compatInfo,
                          int resultCode, String data, Bundle extras, boolean ordered,
                          boolean assumeDelivered, int sendingUser, int processState,
                          int sentFromUid, String sentFromPackage);
}
