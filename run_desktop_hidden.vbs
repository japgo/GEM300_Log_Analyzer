Option Explicit

Dim shell
Dim fso
Dim root
Dim command

Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
root = fso.GetParentFolderName(WScript.ScriptFullName)

command = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File " _
    & Chr(34) & root & "\run_desktop.ps1" & Chr(34)

shell.Run command, 0, False
