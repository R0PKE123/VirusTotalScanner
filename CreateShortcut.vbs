Set WshShell = WScript.CreateObject("WScript.Shell")
shortcutPath = WshShell.ExpandEnvironmentStrings(WScript.Arguments(0))
Set shortcut = WshShell.CreateShortcut(shortcutPath)
shortcut.TargetPath = WScript.Arguments(1)
args = ""
For i = 2 To WScript.Arguments.Count - 1
    args = args & WScript.Arguments(i) & " "
Next
args = Trim(args)
shortcut.Arguments = args
shortcut.WindowStyle = 1
shortcut.Description = "Start MyJavaApp"
shortcut.Save