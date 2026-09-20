' Forge - GUI launcher (no console window).
'
' Why not just double-click the .bat: a .bat is executed by cmd.exe, which is
' a console program, so Windows always allocates a black console window for it.
' The dependency check below (import yaml, tkinter) takes a few hundred ms, so
' that black box stays on screen long enough to see before it disappears. A
' .bat has no way to hide its own console - this was reported as "a black box
' flashes when opening the GUI".
'
' wscript.exe is a GUI-subsystem host: it never allocates a console, and every
' child process started below uses window style 0 (hidden). So nothing dark
' appears between the double-click and the Tk window showing up.
'
' Why not a .pyw: on machines where Python came from the Python Install
' Manager, .pyw has no file association at all, and double-clicking one does
' nothing whatsoever - a silent failure, which is worse than a flash.
'
' ASCII-only, same rule as the .bat launchers (see forge.bat).

Option Explicit

Dim sh, fso, tmpDir, whereOut, pyw, rc, ts, line, here, gui

Set sh  = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

here     = fso.GetParentFolderName(WScript.ScriptFullName)
gui      = fso.BuildPath(here, "gui.py")
tmpDir   = fso.GetSpecialFolder(2).Path                  ' %TEMP%
whereOut = fso.BuildPath(tmpDir, "forge_where.txt")

' ---- 1. Locate pythonw.exe -------------------------------------------------
' `where` is used instead of a bare "pythonw", for the same reason
' forge.bat does: on jump boxes with a very long PATH, Windows fails to
' resolve the bare name, while `where` still finds it. The output goes to a
' temp file because WshShell.Exec allocates a console of its own; Run with
' window style 0 does not.
On Error Resume Next
fso.DeleteFile whereOut, True
On Error GoTo 0
sh.Run """" & sh.ExpandEnvironmentStrings("%comspec%") & _
       """ /c where pythonw > """ & whereOut & """ 2>nul", 0, True

pyw = ""
If fso.FileExists(whereOut) Then
    Set ts = fso.OpenTextFile(whereOut, 1)
    Do While Not ts.AtEndOfStream
        line = Trim(ts.ReadLine)
        If Len(line) > 0 Then
            pyw = line
            Exit Do
        End If
    Loop
    ts.Close
End If

If Len(pyw) = 0 Then
    MsgBox "pythonw.exe was not found on PATH." & vbCrLf & vbCrLf & _
           "Install Python 3.8+ and tick ""Add Python to PATH"" during setup.", _
           vbCritical, "Forge"
    WScript.Quit 1
End If

' ---- 2. Check dependencies, hidden ----------------------------------------
' Done here rather than inside gui.py: a pythonw.exe failure prints nowhere,
' so a missing PyYAML would make the process vanish with no window and no
' message at all. That silent failure is the thing worth spending a dialog on.
rc = sh.Run("""" & pyw & """ -c ""import yaml, tkinter""", 0, True)
If rc <> 0 Then
    MsgBox "Missing dependency - the GUI cannot start." & vbCrLf & vbCrLf & _
           "Run this in a terminal:" & vbCrLf & _
           "    """ & pyw & """ -m pip install pyyaml" & vbCrLf & vbCrLf & _
           "If tkinter is the missing one, reinstall Python with the tcl/tk" & vbCrLf & _
           "option. The terminal UI is unaffected - use forge.bat.", _
           vbCritical, "Forge"
    WScript.Quit 1
End If

' ---- 3. Launch -------------------------------------------------------------
' Window style 1 (normal), deliberately NOT 0: pythonw.exe has no console to
' hide, and passing SW_HIDE risks the Tk main window starting up hidden.
'
' The cd is best-effort: CurrentDirectory cannot be set to a UNC path, so
' running this from a network share would raise here. gui.py resolves its data
' directory from __file__, not from the cwd, so a failed cd costs nothing -
' and it must not take the launch down with it.
On Error Resume Next
sh.CurrentDirectory = here
On Error GoTo 0
sh.Run """" & pyw & """ """ & gui & """", 1, False
