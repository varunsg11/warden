# Terminal demo for the README, rendered with VHS (https://github.com/charmbracelet/vhs):
#
#   vhs docs/demo.tape        # writes docs/demo.gif
#
# Run from the repo root with the venv active (`warden` on PATH). Offline, no API key.

Output docs/demo.gif

Set Shell "bash"
Set FontSize 15
Set Width 1200
Set Height 720
Set Padding 16
Set TypingSpeed 35ms

Type "# Without Warden: an injected instruction in a support ticket moves money"
Enter
Sleep 600ms
Type "warden baseline --fake | tail -4"
Enter
Sleep 3s

Type "# With Warden: the same injection is denied at the gate"
Enter
Sleep 600ms
Type "warden governed --fake | tail -7"
Enter
Sleep 4s

Type "# 17 attacks, including evasions and in-envelope redirects -- and which check stopped each"
Enter
Sleep 600ms
Type "warden eval | sed -n '/ATTACKS/,/^$/p'"
Enter
Sleep 6s

Type "warden eval | tail -3"
Enter
Sleep 4s
