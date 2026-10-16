# Session 01: Hints

Open only what you need. Each step has a nudge and a more concrete hint.

## 1. Inspect the image

<details>
<summary>Hint 1: Where should you look?</summary>

A recognizable archive does not have to start at byte zero. Compare the first bytes of the firmware with the embedded signatures found by `binwalk`.

</details>

<details>
<summary>Hint 2: How do you find the payload boundary?</summary>

Look for the gzip signature `1f 8b 08`. Try `xxd -s 240 -l 48 gateway-update.bin`. The left-hand column shows **hexadecimal offsets**, not decimal values.

</details>

## 2. Extract the payload

<details>
<summary>Hint 1: Which `dd` options matter?</summary>

Use `skip` to bypass the wrapper. With `bs=1`, the skip value is a byte count. Verify the carved output with `file` before extracting anything.

</details>

<details>
<summary>Hint 2: How do you extract and fingerprint it?</summary>

```bash
dd if=gateway-update.bin of=payload.bin.gz bs=1 skip=256
file payload.bin.gz
tar -tzf payload.bin.gz
mkdir -p extracted
tar -xzf payload.bin.gz -C extracted
sha256sum payload.bin.gz
```

The submission expects the SHA-256 of the **compressed payload**, not the unpacked filesystem.

</details>

## 3. Reconstruct startup behavior

<details>
<summary>Hint 1: Where does the command come from?</summary>

Inspect `extracted/etc/init.d/` and the configuration referenced by its script. A leading `.` in a shell script loads another file into the current shell.

</details>

<details>
<summary>Hint 2: Which command should you submit?</summary>

Resolve the variables from `device.conf`, evaluate the `DEBUG_MODE` condition, then submit the resulting `/usr/bin/telemetry-agent` command with its arguments. The `.` command itself is **not** the startup command.

</details>

## 4. Identify security weaknesses

<details>
<summary>Hint 1: Where are the signals?</summary>

Start with `rg -ni 'debug|token|secret' extracted/`. Look for unsafe configuration defaults and credentials shipped inside the image.

</details>

<details>
<summary>Hint 2: What distinguishes the two findings?</summary>

One concerns the enabled debug mode. The other concerns a credential embedded in the firmware and supplied to a process as an argument. Use short identifiers in `security.weaknesses`, not descriptions.

</details>
