# NAS-Deciphering operator guide

`nas_ea2_decode.py` decrypts 5G NAS messages in an N2 (NGAP) capture and can write a copy of
the capture that Wireshark opens with the NAS already in clear. It handles only messages
protected with 128-5G-EA2 / 128-5G-IA2.

To install the tool, see [Installation and usage](../README.md#installation-and-usage) in the
README.

> **Handle all inputs and outputs as sensitive.** Captures hold subscriber identities and, with
> N12, K_SEAF in clear. The output capture also holds the decrypted NAS, and the terminal output
> holds the keys unless you pass `--no-show-keys`. Do not commit these files or attach them to
> tickets. Keys typed on the command line are also saved in your shell history.

## How to run the tool

Run all commands from the repository folder. Paths below are examples.

**Most common case:** N2 and N12 are in the same capture, so the keys come from the trace.

```sh
uv run python nas_ea2_decode.py --pcap Traces/trace.pcap --out-n2-pcap Traces/trace_plain.pcap
```

If the input is a pcapng, name the output `.pcapng`, because the output keeps the input's format.

**Other cases:**

```sh
# N12 is in a separate capture
uv run python nas_ea2_decode.py --pcap n2.pcap --n12-pcap n12.pcap --out-n2-pcap out.pcap

# The authentication happened before the capture started: give K_AMF
# (for example the KAmf from the AMF's "show subscriber")
uv run python nas_ea2_decode.py --pcap n2.pcap --kamf <64 hex> --out-n2-pcap out.pcap

# You have K_SEAF: give it with the SUPI, and the ABBA if it is not 0000
uv run python nas_ea2_decode.py --pcap n2.pcap --kseaf <64 hex> --supi <IMSI digits> --abba 0000

# List every NAS message, without printing the keys
uv run python nas_ea2_decode.py --pcap n2.pcap --view-msg --no-show-keys

# N12 on a non-standard port, or over TLS
uv run python nas_ea2_decode.py --pcap trace.pcap --n12-port 8080
uv run python nas_ea2_decode.py --pcap trace.pcap --n12-port 443 --tls-keylog sslkeys.log

# NAS PDUs from a text file instead of a capture (tshark is not needed unless you add --n12-pcap)
uv run python nas_ea2_decode.py --list pdus.txt --kamf <64 hex> --view-msg
```

Each line of a `--list` file is `<frame> <UL|DL> <hex>`. Blank lines and text after `#` are
ignored.

When the tool cannot find a key or the SUPI, it asks for it at the terminal. When it is not
running in a terminal, such as in a script, it stops with exit code 1 and names the option to
pass.

## Options

You must give exactly one of `--pcap` or `--list`.

### Input

| Option | Description | Default |
|---|---|---|
| `--pcap FILE` | N2 capture, classic pcap or pcapng. Read with tshark. | |
| `--list FILE` | Text file of NAS PDUs, in place of a capture. | |
| `--amf-ip ADDR` | AMF IPv4 or IPv6 address on N2. Packets sent by this address are downlink and all others are uplink. Used with `--pcap` only. | First readable NAS message with a fixed direction |
| `--tshark PATH` | Path to the tshark program. | `tshark` on your `PATH` |

### Keys and identity

The tool uses keys from the trace and keys from the command line together. Each distinct key
becomes one security context (`ctx#0`, `ctx#1`, ...), and each message is tried against all of
them.

| Option | Description | Default |
|---|---|---|
| `--kseaf HEX` | K_SEAF as 64 hex characters. Repeatable. | Read from N12 |
| `--kseaf-ascii B64` | K_SEAF as base64 text (44 characters). Quote it. Repeatable. | |
| `--kamf HEX` | K_AMF as 64 hex characters. Needs no SUPI. Repeatable. | Mapped K_AMF from GTPv2, if present |
| `--kamf-ascii B64` | K_AMF as base64 text (44 characters). Quote it. Repeatable. | |
| `--supi VALUE` | IMSI digits, with or without `imsi-`. One value, shared by every K_SEAF that has no SUPI of its own. | N12/SBI, then a null-scheme SUCI on N2, then asked for |
| `--abba HEX` | ABBA value from the Authentication Request. One value, shared by all K_SEAF keys. | `0000` |

### N12 signalling

| Option | Description | Default |
|---|---|---|
| `--n12-pcap FILE` | Capture holding N12/SBI signalling. GTPv2 is still read from `--pcap` only. | Same file as `--pcap` |
| `--n12-port PORT` | TCP port to decode as HTTP/2, or as TLS with `--tls-keylog`. Repeatable. | tshark's default decoding |
| `--tls-keylog FILE` | TLS key log (SSLKEYLOGFILE format), used to decrypt N12. | |

### Output and search

| Option | Description | Default |
|---|---|---|
| `--out-n2-pcap FILE` | Writes the decrypted copy of the capture. Needs `--pcap`. **Overwrites an existing file without asking, even the input file.** | No file written |
| `--keep-unverified` | Also decrypts messages whose MAC failed into the output file. The result may be garbage. | Off |
| `--view-msg` | Lists every NAS message with its COUNT, MAC result and plaintext. | Summary only |
| `--show-keys` / `--no-show-keys` | Prints or hides the keys. | Printed |
| `--max-overflow N` | Highest NAS COUNT overflow value tried when matching the MAC. | `255` |

## Expected outputs

### Terminal

A normal run looks like this (values are masked):

```text
5 frames with ciphered NAS (first: frame 32); looking for the keys.

SUPI   = imsi-00101000000XXXX   (from N12 frame 27)
AMF IP = 2001:db8::1   (from Registration Request in frame 4)

ctx#0:   (K_SEAF from N12 frame 27, imsi-00101000000XXXX)
  K_SEAF   = <64 hex>
  K_AMF    = <64 hex>
  K_NASenc = <32 hex>
  K_NASint = <32 hex>

9 NAS messages: 3 plain, 6 MAC verified   (--view-msg to list them)

wrote trace_plain.pcap: 5 packets with NAS decrypted in place (frames 32, 75, 76, 77, 112); everything else is unchanged.
In those packets the security header type is relabelled from 'ciphered' to 'integrity only' so Wireshark decodes the payload; the MAC field is the original one.
```

If no message is ciphered, the tool needs no keys and prints this instead. It does not write an
output file, because the file would be identical to the input.

```text
AMF IP = 2001:db8::1   (from Registration Request in frame 4)

28 NAS messages, none ciphered: nothing to decrypt, so no K_SEAF or SUPI is needed.
out.pcap not written: it would be identical to the input.
```

### Summary line

| Label | Meaning |
|---|---|
| `plain` | The message has no security protection. |
| `MAC verified` | A key and COUNT reproduced the message's MAC, so the result is proven correct. |
| `MAC FAILED` | No key and COUNT reproduced the MAC. See [Check results](#check-results). |
| `not 5GMM` | The outer message does not start with the 5GMM identifier (`0x7E`). It is not processed. |
| `unparsable` | The security header is invalid or the message is too short. |

### `--view-msg` table

```text
 frame dir security header                 COUNT MAC      key       message
     4 UL  plain                               - -                  5GMM Registration Request
           plain NAS: <hex>
    31 DL  integrity (new ctx)                 0 ok       ctx#0     5GMM Security Mode Command
           plain NAS: <hex>
    32 UL  integrity+ciphered (new ctx)        0 ok       ctx#0     5GMM Security Mode Complete
           plain NAS: <hex>
```

The `MAC` column shows `ok`, `FAIL`, or `-` if there is nothing to check. These notes can appear
after the message name:

| Note | Meaning |
|---|---|
| `UNVERIFIED - COUNT/key probably wrong` | A ciphered message failed its MAC. **Do not trust the decoded message.** |
| `MAC not verified, but this message is not ciphered so it is readable` | The content is readable as captured, but the tool could not authenticate it. |
| `already decrypted in the capture; MAC verified over the re-encrypted payload` | Another tool had already decrypted this message in the capture. |

### Output capture

The output has the same format, size, packets, timing and pcapng comments as the input. Only
these bytes change in each decrypted packet:

- **Payload:** the ciphered NAS payload becomes plaintext.
- **Security header type:** "ciphered" becomes "integrity only" (2 to 1, or 4 to 3), so Wireshark
  decodes the payload.
- **SCTP checksum:** it is recalculated.

The MAC and sequence number stay as captured. Because of the relabelling, **the output does not
show whether a message was ciphered on the network**. Use the original capture or the `--view-msg`
table to answer that.

## Check results

A clean run means every ciphered message was decrypted and proven by its MAC. Exit code 0 does not
prove this: see [Exit codes](#exit-codes).

1. **Read the summary line.** `MAC FAILED` should be absent. If it is present, check step 2.

2. **List any failures:**

   ```sh
   uv run python nas_ea2_decode.py --pcap trace.pcap --view-msg --no-show-keys | grep ' FAIL '
   ```

   Rows marked `UNVERIFIED` are ciphered messages that stayed undecrypted. Other `FAIL` rows are
   readable, but not authenticated.

3. **Compare the packet counts.** The number in `N frames with ciphered NAS` should equal the number
   in `wrote ...: N packets with NAS decrypted`. If `wrote` reports fewer, those packets are still
   ciphered in the output. `MAC verified` is often higher than both, because it also counts
   integrity-only messages.

4. **Look for messages that are still ciphered in the output.** Expect no rows from this command:

   ```sh
   tshark -n -r out.pcap -Y 'nas_5gs.security_header_type == 2 || nas_5gs.security_header_type == 4'
   ```

5. **Confirm that the input and output have the same packet count:**

   ```sh
   capinfos -c trace.pcap out.pcap
   ```

6. **Compare SCTP checksum failures.** Run this on both files and expect the same frame numbers. A
   frame that fails only in the output indicates a problem with the rewrite. Failures already in
   the input come from the capture itself.

   ```sh
   tshark -n -r out.pcap -o sctp.checksum:CRC-32C -Y 'sctp.checksum.status == 0' -T fields -e frame.number
   ```

7. **Open the output in Wireshark.** Apply the display filter `nas_5gs.mm.message_type` and check
   that the decrypted packets show message names. No keys or preferences are needed. A frame can
   show two message types, for example a Security Mode Complete that carries a Registration
   Request inside it.

## Exit codes

| Code | Meaning | Examples |
|---|---|---|
| `0` | The run finished. **Decryption may still be incomplete.** | All messages verified; some or all MACs failed; nothing ciphered, so no output file; no NAS found in the capture; rewrite warnings |
| `1` | The run stopped on an error, printed on stderr. | tshark missing or failed; capture missing or unreadable; invalid key, SUPI or `--amf-ip`; key or SUPI not found outside a terminal; prompt cancelled; output folder missing (shown as a Python traceback) |
| `2` | The command line is wrong. Usage is printed. | Neither `--pcap` nor `--list`; both together; `--out-n2-pcap` with `--list`; invalid `--abba` |

To detect incomplete decryption in a script, check the log as well as the exit code:

```sh
uv run python nas_ea2_decode.py --pcap trace.pcap --no-show-keys --out-n2-pcap out.pcap > run.log 2>&1
rc=$?
if [ $rc -ne 0 ]; then echo "error (exit $rc)"
elif grep -q 'MAC FAILED' run.log; then echo "incomplete: some MACs failed"
else echo "complete"
fi
```

A run that finds nothing to decrypt also reports `complete` here. Search `run.log` for
`none ciphered` if your script expects an output file.

## Basic troubleshooting

### Errors that stop the run

| Message | Likely cause | Action |
|---|---|---|
| `tshark not found` | tshark is not installed or not on `PATH`. | Install Wireshark/tshark, or pass `--tshark PATH`. |
| `tshark failed: ... doesn't exist` | The capture path is wrong. | Correct the path. |
| `tshark failed: ... cut short in the middle of a packet` | The capture is truncated. | Run `editcap broken.pcap repaired.pcap`, then use the repaired file. editcap prints the same message but still saves the complete packets. Anything after the cut is lost. |
| `K_SEAF or K_AMF ... could not be found` | The trace has no authentication or EPS context for this UE, for example a GUTI registration using an earlier security context. | Pass `--kamf`, or `--kseaf` with `--supi`. If N12 is present, see `--n12-port` and `--tls-keylog`. |
| `SUPI ... could not be found` | A K_SEAF has no SUPI: the identity is a 5G-GUTI or concealed SUCI, or several UEs appear in the SBI signalling. | Pass `--supi`, or use `--kamf`, which needs no SUPI. |
| `--amf-ip not given and no readable NAS message ...` | The AMF cannot be identified because no readable message has a fixed direction. | Pass `--amf-ip`. |
| `FileNotFoundError` traceback on the output file | The output folder does not exist. | Create the folder or correct the path. |

### MAC failures (exit code 0)

| Symptom | Likely cause | Action |
|---|---|---|
| Every protected message fails | The key is wrong, or belongs to a different authentication; or the SUPI or ABBA is wrong. | Check the key source. Get the ABBA from the Authentication Request and the SUPI from the trace or the AMF. |
| Messages in only one direction fail | The AMF address is wrong, or the AMF uses several addresses, so downlink is treated as uplink. | Compare the printed `AMF IP` with the trace and set `--amf-ip`. If there are several AMF addresses, filter the capture to one and run the tool per address. |
| Only some messages fail, mostly for one UE or before a certain frame | The context for those messages was set up before the capture started, or a key is missing. | Add the missing key with `--kamf` or `--kseaf`. |
| Failures just before a 5G Security Mode Command in a 4G to 5G procedure | Those messages may use SNOW 3G (5G-IA1/EA1), which is not supported. | No fix available. Later messages should verify. |
| Failures only at high COUNT values | `--max-overflow` was set too low. | Return it to the default of 255. |
| Decoded messages look like garbage | The output was written with `--keep-unverified`. | Run again without that option, and fix the failures first. |

### Unexpected output

| Symptom | Likely cause | Action |
|---|---|---|
| `tshark returned no NAS PDUs` and `0 NAS messages` | The capture has no NGAP with NAS, or tshark does not recognise it as NGAP. | Run `tshark -n -r trace.pcap -Y ngap` and check that it lists packets. |
| Output file was not created | Nothing in the trace is ciphered. | No action needed. The input is already readable. |
| `wrote ...: 0 packets with NAS decrypted` | No ciphered message verified. The output has the same content as the input. | Resolve the MAC failures above. |
| `WARNING: frame N: NAS PDU bytes not found in the packet` | The PDU spans several packets. | That message cannot be rewritten. Read it with `--view-msg`. |
| `WARNING: frame N: SCTP header not located, checksum NOT updated` | The link type or packet layout is not supported. | The NAS is rewritten, but Wireshark may flag the SCTP checksum on that frame. |
| `WARNING: N12 frame N: K_SEAF ... is not 32 bytes of hex, ignored` | The trace holds a K_SEAF value in an unexpected form. | Provide the key with `--kseaf` or `--kamf`. |

## Known limitations

**Algorithms and access**

- Only 128-5G-EA2 and 128-5G-IA2 are supported. Messages using other algorithms fail the MAC check.
- Only 3GPP access is supported (bearer 1).
- Only IMSI-type SUPIs are supported.

**Keys and identity**

- A key must be in the trace (N12 authentication or GTPv2 EPS context) or be given on the command
  line. Otherwise, the messages cannot be decrypted.
- A concealed SUCI (ECIES Profile A/B) or a 5G-GUTI does not reveal the SUPI.
- `--supi` and `--abba` take one value per run. To use several `--kseaf` keys with different SUPIs
  or ABBA values, use separate runs, or use `--kamf`, which needs neither.

**Direction and COUNT**

- Only one AMF address is used to tell downlink from uplink.
- COUNT tracking is only a hint, so heavily interleaved multi-UE traces fall back to the full COUNT
  search. Results stay correct, but the run is slower.

**Input and output files**

- `--out-n2-pcap` supports Ethernet (with VLAN), Linux cooked capture v1 and v2, and raw IP, over
  IPv4 and IPv6.
- The output always keeps the input's format. A classic pcap cannot become a pcapng, and has no
  comments to keep.
- A NAS PDU split across several packets cannot be rewritten.
- The whole capture is loaded into memory when writing the output, so very large files need
  matching free memory.

**Reporting**

- Exit code 0 does not mean all messages were decrypted.
- The output capture does not show which messages were originally ciphered.
