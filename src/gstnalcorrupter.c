#include <gst/base/gstbasetransform.h>
#include <gst/gst.h>
#include <string.h>

#ifndef PACKAGE
#define PACKAGE "gst-corrupter"
#endif

typedef enum {
  GST_NAL_CORRUPTER_CODEC_UNKNOWN = 0,
  GST_NAL_CORRUPTER_CODEC_H264,
  GST_NAL_CORRUPTER_CODEC_H265
} GstNalCorrupterCodec;

typedef enum {
  GST_NAL_CORRUPTER_STREAM_ANNEXB = 0,
  GST_NAL_CORRUPTER_STREAM_LENGTH_PREFIXED
} GstNalCorrupterStreamFormat;

typedef enum {
  GST_NAL_CORRUPTER_MODE_FLIP_BIT = 0,
  GST_NAL_CORRUPTER_MODE_ZERO_BYTE,
  GST_NAL_CORRUPTER_MODE_RANDOM_BYTE,
  GST_NAL_CORRUPTER_MODE_NUKE_NAL
} GstNalCorrupterMode;

typedef struct {
  guint offset;
  guint size;
} GstNalUnit;

typedef struct _GstNalCorrupter {
  GstBaseTransform parent;

  gdouble nal_corruption_probability;
  guint bytes_per_nal;
  guint max_nals_per_buffer;
  guint length_field_size;
  gboolean protect_config;
  gboolean only_corrupt_slices;
  GstNalCorrupterMode mode;

  guint seed;
  GRand *rand;

  GstNalCorrupterCodec codec;
  GstNalCorrupterStreamFormat stream_format;
} GstNalCorrupter;

typedef struct _GstNalCorrupterClass {
  GstBaseTransformClass parent_class;
} GstNalCorrupterClass;

#define GST_TYPE_NAL_CORRUPTER (gst_nal_corrupter_get_type())
#define GST_NAL_CORRUPTER(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST((obj), GST_TYPE_NAL_CORRUPTER, GstNalCorrupter))

G_DEFINE_TYPE(GstNalCorrupter, gst_nal_corrupter, GST_TYPE_BASE_TRANSFORM)

GST_DEBUG_CATEGORY_STATIC(gst_nal_corrupter_debug);
#define GST_CAT_DEFAULT gst_nal_corrupter_debug

enum {
  PROP_0,
  PROP_MODE,
  PROP_NAL_CORRUPTION_PROBABILITY,
  PROP_BYTES_PER_NAL,
  PROP_MAX_NALS_PER_BUFFER,
  PROP_PROTECT_CONFIG,
  PROP_ONLY_CORRUPT_SLICES,
  PROP_LENGTH_FIELD_SIZE,
  PROP_SEED
};

static GType
gst_nal_corrupter_mode_get_type(void)
{
  static gsize type = 0;
  static const GEnumValue values[] = {
    {GST_NAL_CORRUPTER_MODE_FLIP_BIT, "Flip one or more random bits", "flip-bit"},
    {GST_NAL_CORRUPTER_MODE_ZERO_BYTE, "Overwrite random bytes with zero", "zero-byte"},
    {GST_NAL_CORRUPTER_MODE_RANDOM_BYTE, "Overwrite random bytes with random values",
        "random-byte"},
    {GST_NAL_CORRUPTER_MODE_NUKE_NAL, "Zero full NAL payload (except header)", "nuke-nal"},
    {0, NULL, NULL}
  };

  if (g_once_init_enter(&type)) {
    GType new_type = g_enum_register_static("GstNalCorrupterMode", values);
    g_once_init_leave(&type, new_type);
  }

  return (GType) type;
}

static gboolean
is_h264_config_nal(guint8 nal_header)
{
  guint8 nal_type = nal_header & 0x1f;
  return nal_type == 7 || nal_type == 8;
}

static gboolean
is_h265_config_nal(const guint8 *nal, guint size)
{
  guint8 nal_type;

  if (size < 2) {
    return FALSE;
  }

  nal_type = (nal[0] >> 1) & 0x3f;
  return nal_type == 32 || nal_type == 33 || nal_type == 34;
}

static gboolean
is_config_nal(const GstNalCorrupter *self, const guint8 *nal, guint size)
{
  if (size == 0) {
    return FALSE;
  }

  switch (self->codec) {
    case GST_NAL_CORRUPTER_CODEC_H264:
      return is_h264_config_nal(nal[0]);
    case GST_NAL_CORRUPTER_CODEC_H265:
      return is_h265_config_nal(nal, size);
    default:
      return FALSE;
  }
}

static gboolean
is_h264_slice_nal(guint8 nal_header)
{
  guint8 nal_type = nal_header & 0x1f;
  /* NAL types 1-5 are slice types:
   * 1 = Non-IDR slice
   * 2 = Slice data partition A
   * 3 = Slice data partition B
   * 4 = Slice data partition C
   * 5 = IDR slice */
  return nal_type >= 1 && nal_type <= 5;
}

static gboolean
is_h265_slice_nal(const guint8 *nal, guint size)
{
  guint8 nal_type;

  if (size < 2) {
    return FALSE;
  }

  nal_type = (nal[0] >> 1) & 0x3f;
  /* NAL types 0-9, 16-21 are slice types:
   * 0-9 = Various slice types (TRAIL, TSA, STSA, RADL, RASL, etc.)
   * 16-21 = IDR and CRA slices */
  return (nal_type >= 0 && nal_type <= 9) || (nal_type >= 16 && nal_type <= 21);
}

static gboolean
is_slice_nal(const GstNalCorrupter *self, const guint8 *nal, guint size)
{
  if (size == 0) {
    return FALSE;
  }

  switch (self->codec) {
    case GST_NAL_CORRUPTER_CODEC_H264:
      return is_h264_slice_nal(nal[0]);
    case GST_NAL_CORRUPTER_CODEC_H265:
      return is_h265_slice_nal(nal, size);
    default:
      return FALSE;
  }
}

static gboolean
find_start_code(const guint8 *data, gsize size, gsize from, gsize *pos,
    guint *start_code_size)
{
  gsize i;

  if (size < 3 || from >= size - 2) {
    return FALSE;
  }

  for (i = from; i + 3 <= size; ++i) {
    if (i + 4 <= size && data[i] == 0x00 && data[i + 1] == 0x00 &&
        data[i + 2] == 0x00 && data[i + 3] == 0x01) {
      *pos = i;
      *start_code_size = 4;
      return TRUE;
    }

    if (data[i] == 0x00 && data[i + 1] == 0x00 && data[i + 2] == 0x01) {
      *pos = i;
      *start_code_size = 3;
      return TRUE;
    }
  }

  return FALSE;
}

static void
collect_annexb_nals(const guint8 *data, gsize size, GArray *nals)
{
  gsize start_pos;
  guint start_code_size;

  if (!find_start_code(data, size, 0, &start_pos, &start_code_size)) {
    return;
  }

  while (TRUE) {
    gsize nal_start = start_pos + start_code_size;
    gsize next_pos;
    guint next_start_code_size;
    GstNalUnit nal;

    if (nal_start >= size) {
      break;
    }

    if (find_start_code(data, size, nal_start, &next_pos, &next_start_code_size)) {
      nal.offset = (guint) nal_start;
      nal.size = (guint) (next_pos - nal_start);
      if (nal.size > 0) {
        g_array_append_val(nals, nal);
      }

      start_pos = next_pos;
      start_code_size = next_start_code_size;
      continue;
    }

    nal.offset = (guint) nal_start;
    nal.size = (guint) (size - nal_start);
    if (nal.size > 0) {
      g_array_append_val(nals, nal);
    }
    break;
  }
}

static void
collect_length_prefixed_nals(const guint8 *data, gsize size, guint len_size,
    GArray *nals)
{
  gsize pos = 0;

  if (len_size < 1 || len_size > 4) {
    return;
  }

  while (pos + len_size <= size) {
    guint32 nal_len = 0;
    guint i;
    GstNalUnit nal;

    for (i = 0; i < len_size; ++i) {
      nal_len = (nal_len << 8) | data[pos + i];
    }
    pos += len_size;

    if (nal_len == 0 || pos + nal_len > size) {
      break;
    }

    nal.offset = (guint) pos;
    nal.size = nal_len;
    g_array_append_val(nals, nal);

    pos += nal_len;
  }
}

static void
flip_random_bit(GstNalCorrupter *self, guint8 *payload, guint payload_len)
{
  guint idx;
  guint bit;

  if (payload_len == 0) {
    return;
  }

  idx = g_rand_int_range(self->rand, 0, payload_len);
  bit = (guint) g_rand_int_range(self->rand, 0, 8);
  payload[idx] ^= (guint8) (1u << bit);
}

static void
zero_random_byte(GstNalCorrupter *self, guint8 *payload, guint payload_len)
{
  guint idx;

  if (payload_len == 0) {
    return;
  }

  idx = g_rand_int_range(self->rand, 0, payload_len);
  payload[idx] = 0x00;
}

static void
randomize_random_byte(GstNalCorrupter *self, guint8 *payload, guint payload_len)
{
  guint idx;

  if (payload_len == 0) {
    return;
  }

  idx = g_rand_int_range(self->rand, 0, payload_len);
  payload[idx] = (guint8) g_rand_int_range(self->rand, 0, 256);
}

static void
corrupt_nal_payload(GstNalCorrupter *self, guint8 *nal, guint nal_size)
{
  guint payload_offset;
  guint payload_len;
  guint i;

  if (nal_size <= 1) {
    return;
  }

  payload_offset = 1;
  payload_len = nal_size - payload_offset;

  if (self->mode == GST_NAL_CORRUPTER_MODE_NUKE_NAL) {
    memset(nal + payload_offset, 0x00, payload_len);
    return;
  }

  for (i = 0; i < self->bytes_per_nal; ++i) {
    switch (self->mode) {
      case GST_NAL_CORRUPTER_MODE_FLIP_BIT:
        flip_random_bit(self, nal + payload_offset, payload_len);
        break;
      case GST_NAL_CORRUPTER_MODE_ZERO_BYTE:
        zero_random_byte(self, nal + payload_offset, payload_len);
        break;
      case GST_NAL_CORRUPTER_MODE_RANDOM_BYTE:
        randomize_random_byte(self, nal + payload_offset, payload_len);
        break;
      case GST_NAL_CORRUPTER_MODE_NUKE_NAL:
      default:
        break;
    }
  }
}

static gboolean
gst_nal_corrupter_set_caps(GstBaseTransform *base, GstCaps *incaps,
    GstCaps *outcaps)
{
  GstNalCorrupter *self = GST_NAL_CORRUPTER(base);
  const GstStructure *s;
  const gchar *name;
  const gchar *stream_format;

  (void) outcaps;

  self->codec = GST_NAL_CORRUPTER_CODEC_UNKNOWN;
  self->stream_format = GST_NAL_CORRUPTER_STREAM_ANNEXB;

  if (incaps == NULL || gst_caps_get_size(incaps) == 0) {
    return FALSE;
  }

  s = gst_caps_get_structure(incaps, 0);
  name = gst_structure_get_name(s);

  if (g_strcmp0(name, "video/x-h264") == 0) {
    self->codec = GST_NAL_CORRUPTER_CODEC_H264;
  } else if (g_strcmp0(name, "video/x-h265") == 0) {
    self->codec = GST_NAL_CORRUPTER_CODEC_H265;
  } else {
    return FALSE;
  }

  stream_format = gst_structure_get_string(s, "stream-format");
  if (stream_format != NULL &&
      (g_strcmp0(stream_format, "avc") == 0 ||
          g_strcmp0(stream_format, "avc3") == 0 ||
          g_strcmp0(stream_format, "hvc1") == 0 ||
          g_strcmp0(stream_format, "hev1") == 0)) {
    self->stream_format = GST_NAL_CORRUPTER_STREAM_LENGTH_PREFIXED;
  }

  GST_DEBUG_OBJECT(self, "Configured codec=%d stream_format=%d", self->codec,
      self->stream_format);

  return TRUE;
}

static GstFlowReturn
gst_nal_corrupter_transform_ip(GstBaseTransform *base, GstBuffer *buf)
{
  GstNalCorrupter *self = GST_NAL_CORRUPTER(base);
  GstMapInfo map;
  GArray *nals;
  guint i;
  guint corrupted = 0;

  if (self->codec == GST_NAL_CORRUPTER_CODEC_UNKNOWN) {
    return GST_FLOW_OK;
  }

  if (!gst_buffer_map(buf, &map, GST_MAP_READWRITE)) {
    GST_WARNING_OBJECT(self, "Failed to map buffer");
    return GST_FLOW_OK;
  }

  nals = g_array_new(FALSE, FALSE, sizeof(GstNalUnit));

  if (self->stream_format == GST_NAL_CORRUPTER_STREAM_ANNEXB) {
    collect_annexb_nals(map.data, map.size, nals);
  } else {
    collect_length_prefixed_nals(map.data, map.size, self->length_field_size, nals);
  }

  for (i = 0; i < nals->len; ++i) {
    GstNalUnit *nal = &g_array_index(nals, GstNalUnit, i);
    guint8 *nal_data;

    if (self->max_nals_per_buffer > 0 && corrupted >= self->max_nals_per_buffer) {
      break;
    }

    if (nal->offset + nal->size > map.size || nal->size == 0) {
      continue;
    }

    if (g_rand_double(self->rand) > self->nal_corruption_probability) {
      continue;
    }

    nal_data = map.data + nal->offset;
    if (self->protect_config && is_config_nal(self, nal_data, nal->size)) {
      continue;
    }

    if (self->only_corrupt_slices && !is_slice_nal(self, nal_data, nal->size)) {
      continue;
    }

    corrupt_nal_payload(self, nal_data, nal->size);
    corrupted++;
  }

  if (corrupted > 0) {
    GST_LOG_OBJECT(self, "Corrupted %u NAL units in buffer", corrupted);
  }

  g_array_free(nals, TRUE);
  gst_buffer_unmap(buf, &map);
  return GST_FLOW_OK;
}

static void
gst_nal_corrupter_set_property(GObject *object, guint prop_id,
    const GValue *value, GParamSpec *pspec)
{
  GstNalCorrupter *self = GST_NAL_CORRUPTER(object);

  switch (prop_id) {
    case PROP_MODE:
      self->mode = (GstNalCorrupterMode) g_value_get_enum(value);
      break;
    case PROP_NAL_CORRUPTION_PROBABILITY:
      self->nal_corruption_probability = g_value_get_double(value);
      break;
    case PROP_BYTES_PER_NAL:
      self->bytes_per_nal = g_value_get_uint(value);
      break;
    case PROP_MAX_NALS_PER_BUFFER:
      self->max_nals_per_buffer = g_value_get_uint(value);
      break;
    case PROP_PROTECT_CONFIG:
      self->protect_config = g_value_get_boolean(value);
      break;
    case PROP_ONLY_CORRUPT_SLICES:
      self->only_corrupt_slices = g_value_get_boolean(value);
      break;
    case PROP_LENGTH_FIELD_SIZE:
      self->length_field_size = g_value_get_uint(value);
      break;
    case PROP_SEED:
      self->seed = g_value_get_uint(value);
      if (self->rand != NULL) {
        g_rand_set_seed(self->rand, self->seed);
      }
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
      break;
  }
}

static void
gst_nal_corrupter_get_property(GObject *object, guint prop_id, GValue *value,
    GParamSpec *pspec)
{
  GstNalCorrupter *self = GST_NAL_CORRUPTER(object);

  switch (prop_id) {
    case PROP_MODE:
      g_value_set_enum(value, self->mode);
      break;
    case PROP_NAL_CORRUPTION_PROBABILITY:
      g_value_set_double(value, self->nal_corruption_probability);
      break;
    case PROP_BYTES_PER_NAL:
      g_value_set_uint(value, self->bytes_per_nal);
      break;
    case PROP_MAX_NALS_PER_BUFFER:
      g_value_set_uint(value, self->max_nals_per_buffer);
      break;
    case PROP_PROTECT_CONFIG:
      g_value_set_boolean(value, self->protect_config);
      break;
    case PROP_ONLY_CORRUPT_SLICES:
      g_value_set_boolean(value, self->only_corrupt_slices);
      break;
    case PROP_LENGTH_FIELD_SIZE:
      g_value_set_uint(value, self->length_field_size);
      break;
    case PROP_SEED:
      g_value_set_uint(value, self->seed);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
      break;
  }
}

static void
gst_nal_corrupter_dispose(GObject *object)
{
  GstNalCorrupter *self = GST_NAL_CORRUPTER(object);

  if (self->rand != NULL) {
    g_rand_free(self->rand);
    self->rand = NULL;
  }

  G_OBJECT_CLASS(gst_nal_corrupter_parent_class)->dispose(object);
}

static void
gst_nal_corrupter_class_init(GstNalCorrupterClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(klass);
  GstElementClass *element_class = GST_ELEMENT_CLASS(klass);
  GstBaseTransformClass *base_class = GST_BASE_TRANSFORM_CLASS(klass);
  GstCaps *caps;

  gobject_class->set_property = gst_nal_corrupter_set_property;
  gobject_class->get_property = gst_nal_corrupter_get_property;
  gobject_class->dispose = gst_nal_corrupter_dispose;

  g_object_class_install_property(gobject_class, PROP_MODE,
      g_param_spec_enum("mode", "Corruption mode",
          "How selected NAL units are corrupted", gst_nal_corrupter_mode_get_type(),
          GST_NAL_CORRUPTER_MODE_FLIP_BIT,
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property(gobject_class, PROP_NAL_CORRUPTION_PROBABILITY,
      g_param_spec_double("nal-corruption-probability", "NAL corruption probability",
          "Probability [0.0..1.0] that a parsed NAL is corrupted", 0.0, 1.0, 0.02,
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property(gobject_class, PROP_BYTES_PER_NAL,
      g_param_spec_uint("bytes-per-nal", "Bytes per NAL",
          "Number of random byte mutations for each selected NAL", 1, 64, 1,
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property(gobject_class, PROP_MAX_NALS_PER_BUFFER,
      g_param_spec_uint("max-nals-per-buffer", "Max NALs per buffer",
          "Maximum number of NALs to corrupt in a single buffer (0 = unlimited)",
          0, G_MAXUINT, 0, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property(gobject_class, PROP_PROTECT_CONFIG,
      g_param_spec_boolean("protect-config", "Protect VPS/SPS/PPS",
          "Do not corrupt codec configuration NALs", TRUE,
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property(gobject_class, PROP_ONLY_CORRUPT_SLICES,
      g_param_spec_boolean("only-corrupt-slices", "Only corrupt slices",
          "Only corrupt slice NAL units (ignore all non-slice NALs)", FALSE,
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property(gobject_class, PROP_LENGTH_FIELD_SIZE,
      g_param_spec_uint("length-field-size", "Length field size",
          "NAL length field size for avc/hvc1 streams (bytes)", 1, 4, 4,
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property(gobject_class, PROP_SEED,
      g_param_spec_uint("seed", "Random seed",
          "Deterministic random seed used for reproducible corruption", 0,
          G_MAXUINT, 1, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  caps = gst_caps_from_string(
      "video/x-h264, stream-format=(string){ byte-stream, avc, avc3 }, "
      "alignment=(string){ au, nal }; "
      "video/x-h265, stream-format=(string){ byte-stream, hvc1, hev1 }, "
      "alignment=(string){ au, nal }");

  gst_element_class_add_pad_template(element_class,
      gst_pad_template_new("sink", GST_PAD_SINK, GST_PAD_ALWAYS, caps));
  gst_element_class_add_pad_template(element_class,
      gst_pad_template_new("src", GST_PAD_SRC, GST_PAD_ALWAYS, caps));
  gst_caps_unref(caps);

  gst_element_class_set_static_metadata(element_class,
      "NAL corrupter", "Codec/Filter/Video",
      "Intentionally corrupts H.264/H.265 NAL units for decoder robustness testing",
      "GitHub Copilot");

  base_class->set_caps = GST_DEBUG_FUNCPTR(gst_nal_corrupter_set_caps);
  base_class->transform_ip = GST_DEBUG_FUNCPTR(gst_nal_corrupter_transform_ip);

  GST_DEBUG_CATEGORY_INIT(gst_nal_corrupter_debug, "nalcorrupter", 0,
      "NAL corrupter element");
}

static void
gst_nal_corrupter_init(GstNalCorrupter *self)
{
  self->nal_corruption_probability = 0.02;
  self->bytes_per_nal = 1;
  self->max_nals_per_buffer = 0;
  self->protect_config = TRUE;
  self->only_corrupt_slices = FALSE;
  self->mode = GST_NAL_CORRUPTER_MODE_FLIP_BIT;
  self->length_field_size = 4;
  self->seed = 1;
  self->codec = GST_NAL_CORRUPTER_CODEC_UNKNOWN;
  self->stream_format = GST_NAL_CORRUPTER_STREAM_ANNEXB;
  self->rand = g_rand_new_with_seed(self->seed);

  gst_base_transform_set_in_place(GST_BASE_TRANSFORM(self), TRUE);
  gst_base_transform_set_passthrough(GST_BASE_TRANSFORM(self), FALSE);
}

static gboolean
plugin_init(GstPlugin *plugin)
{
  return gst_element_register(plugin, "nalcorrupter", GST_RANK_NONE,
      GST_TYPE_NAL_CORRUPTER);
}

GST_PLUGIN_DEFINE(
    GST_VERSION_MAJOR,
    GST_VERSION_MINOR,
    nalcorrupter,
    "NAL corrupter plugin for H.264/H.265 streams",
    plugin_init,
    "0.1.0",
    "LGPL",
    PACKAGE,
    "https://gstreamer.freedesktop.org/")
