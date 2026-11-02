### Changed: every rule scans in linear time, checked on 1 MiB of adversarial text (FR-E5 t4)

Some rules rescanned the same text from every start they found, so a file made of many
starts took far too long: `rce.shell_true` and `rce.eval_b64` were quadratic (1.4 s and
2.4 s on 64 KiB of `subprocess.run(` or `eval(` repeated; 1 MiB would take minutes), and
`destroy.rm_rf`, `exfil.secret_env_read`, `inject.exfil_instr` and `inject.read_then_send`
took 0.4 to 3 s per MiB on Python 3.9. Each now takes at most about 0.4 s per MiB of its
worst input, and `tests/test_perf.py` holds every rule and every scan-surface regex to 1 s
of CPU time on 1 MiB of each of its adversarial inputs (and the scan loops to linear growth).

What a rule finds is unchanged, except:

- `rce.shell_true` and `rce.eval_b64` look for `shell=True` or a base64 decode within 400
  characters of the call (it was any distance inside the parentheses).
- `destroy.rm_rf` looks for the flags and the target in the next 256 words of the command
  (it was 32, so more padded commands are caught), and reports one finding per command, at
  its first `rm` word: a command such as `rm a rm b rm -rf /` was reported at each `rm`
  whose 32 words held flags and target.
- `inject.exfil_instr` allows 41 characters between `to` and an `http://` URL (40 for
  `https://`, as before).
- Where a rule's window held another start of the same rule (another `subprocess` call,
  `eval(`, `$`, read/cat/open, or send/post/upload verb), the finding is now reported at
  that later start, which matches the same text: the same line, unless the window crossed
  a line break.
