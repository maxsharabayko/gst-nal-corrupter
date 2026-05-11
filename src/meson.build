gst_dep = dependency('gstreamer-1.0', version: '>=1.18')
gst_base_dep = dependency('gstreamer-base-1.0', version: '>=1.18')

shared_module(
  'gstnalcorrupter',
  ['gstnalcorrupter.c'],
  dependencies: [gst_dep, gst_base_dep],
  install: true,
  install_dir: join_paths(get_option('libdir'), 'gstreamer-1.0')
)
