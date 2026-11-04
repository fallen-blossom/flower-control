# Traceable local recording encoder

This independent build keeps Flower's existing PNG-frame concat → pad →
H.264/MP4 recording path. It does not modify an installed encoder, installer,
plugin or `ENCODER.json`.

The intended incorporated third-party source set is FFmpeg 8.1.1, one pinned
x264 revision and zlib 1.3.2. Automatic external-library detection, networking,
unneeded devices and unrelated codecs are disabled. Compiler and assembler
packages come from the official MSYS2 distribution, with independently
published SHA256 values. They are extracted into the explicit build workspace
and never installed into an existing MSYS2 tree or the system PATH.

`prepare.py` accepts a fixed `inputs.lock.json` and verified local input directory,
verifies both sides of copies into the build workspace, and extracts only
verified inputs. Git inputs use the separately
assessed repository workflow and an independent canonical `git archive` digest;
that digest must not be confused with a GitLab compressed-archive checksum.

The public build is portable and offline: use Python 3.14 or later (for built-in
`.tar.zst` extraction), provide `--inputs-dir`, `--work-root` and the existing
official MSYS2 shell location. It does not need a private control plane.
This development run used its host's controlled quarantine/promotion workflow;
the optional acquisition adapter requires explicit control-tool and staging
arguments and never overrides that downloader's policy. Build workspaces retain
at least 10 GiB free. No unrelated files are cleaned.

All source archives, the exact recipe and configuration, local patches (if any),
component license texts, the toolchain manifest, generated build evidence and
recording/decode verification must accompany the final source bundle. A build
success by itself does not establish complete redistribution review.

Run the portable build with verified source/package archives in a local directory:

```text
python prepare.py --offline --lock inputs.lock.json --work-root D:/encoder-build --inputs-dir D:/verified-inputs
python build.py --lock inputs.lock.json --work-root D:/encoder-build --msys-root D:/msys64 --jobs 4
python verify_encoder.py --encoder D:/encoder-build/output/ffmpeg.exe --probe D:/encoder-build/output/ffprobe.exe --output D:/encoder-build/check
python package_sources.py --lock inputs.lock.json --work-root D:/encoder-build --msys-root D:/msys64 --verification D:/encoder-build/check/verification.json
```

`verify_encoder.py` checks the existing VFR presentation timestamps, padding,
H.264/MP4 output, progress completion and decoded frame colors. Its optional
`--reference-encoder` compares the same owned fixture with an already-admitted
encoder. The short B-frame fixture's MP4 container duration differs from the
last presentation timestamp in both builds; container duration is recorded,
not substituted for the presentation-timestamp oracle. This does not claim
foreground recording acceptance or byte-for-byte reproducibility across hosts.
