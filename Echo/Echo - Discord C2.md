
This bot is meant to allow command execution via Discord. **It is a RAT**.

The iterations/versions present are the ones I created during my research of using Discord as C2.
- `v1` - basic bot. Executes commands via `!exec`. Uses `powershell` for Windows and `sh` for Mac/Linux.
- `v2` - iteration of v1 with 3 features:
	- switch between shell (`powershell` | `cmd` | `/bin/sh` | `/bin/bash`)
	- poison cache - forensic evasion
	- delete cache - forensic evasion
	- self destruct

---
