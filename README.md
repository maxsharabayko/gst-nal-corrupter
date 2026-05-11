# gst-corrupter

A GStreamer plugin for intentionally corrupting H.264/H.265 NAL units after an encoder.

## Element

- Name: `nalcorrupter`
- Type: in-place `GstBaseTransform`
- Use case: fuzzing/robustness testing of decoder stability with controlled stream corruption.

## Features

- Supports both `video/x-h264` and `video/x-h265`
- Supports Annex-B (`byte-stream`) and length-prefixed (`avc`, `avc3`, `hvc1`, `hev1`)
- Configurable corruption modes:
  - `flip-bit`: flip random bits
  - `zero-byte`: replace random bytes with zero
  - `random-byte`: replace random bytes with random values
  - `nuke-nal`: keep NAL header, zero entire payload
- Configurable corruption probability per NAL and number of byte mutations per selected NAL
- Optional protection of VPS/SPS/PPS NALs

## Build

```bash
meson setup build
meson compile -C build
meson install -C build
```

If you want to avoid a system install, point `GST_PLUGIN_PATH` at your build output:

```bash
export GST_PLUGIN_PATH="$PWD/build/src:$GST_PLUGIN_PATH"
```

## Inspect

```bash
gst-inspect-1.0 nalcorrupter
```

## Example pipelines

### H.264 encoder -> corrupter -> parser -> decoder

```bash
gst-launch-1.0 -v \
  videotestsrc is-live=true pattern=smpte ! video/x-raw,width=1280,height=720,framerate=30/1 ! \
  x264enc tune=zerolatency key-int-max=30 ! \
  nalcorrupter mode=flip-bit nal-corruption-probability=0.05 bytes-per-nal=2 ! \
  h264parse ! avdec_h264 ! fakesink sync=false
```

### H.265 encoder -> corrupter -> parser -> decoder

```bash
gst-launch-1.0 -v \
  videotestsrc is-live=true ! x265enc ! \
  nalcorrupter mode=random-byte nal-corruption-probability=0.03 protect-config=true ! \
  h265parse ! avdec_h265 ! fakesink sync=false
```

## Notes

- Intentionally generated streams may be undecodable or cause visible artifacts by design.
- Start with low corruption probability and increase gradually.
- Keep parser and decoder in the same pipeline while tuning corruption parameters.
