package org.lsposed.lspromise;

import android.os.Handler;
import android.os.Looper;
import android.telecom.Connection;
import android.telecom.ConnectionRequest;
import android.telecom.ConnectionService;
import android.telecom.DisconnectCause;
import android.telecom.PhoneAccountHandle;

public class MyConnectionService extends ConnectionService {
    @Override public Connection onCreateIncomingConnection(PhoneAccountHandle connectionManagerPhoneAccount, ConnectionRequest request) {
        Connection connection = new Connection() {};
        new Handler(Looper.getMainLooper()).postDelayed(
                () -> connection.setDisconnected(new DisconnectCause(DisconnectCause.UNKNOWN)), 5000);
        return connection;
    }
}
