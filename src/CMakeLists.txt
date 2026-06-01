# Define the plugin as a shared module
add_library(gstnalcorrupter MODULE
	gstnalcorrupter.c
)

# Set target properties
set_target_properties(gstnalcorrupter PROPERTIES
	PREFIX ""
	OUTPUT_NAME "gstnalcorrupter"
)

# Include directories
target_include_directories(gstnalcorrupter PRIVATE
	${GSTREAMER_INCLUDE_DIRS}
	${GSTREAMER_BASE_INCLUDE_DIRS}
)

# Link directories
target_link_directories(gstnalcorrupter PRIVATE
	${GSTREAMER_LIBRARY_DIRS}
	${GSTREAMER_BASE_LIBRARY_DIRS}
)

# Link libraries
target_link_libraries(gstnalcorrupter
	${GSTREAMER_LIBRARIES}
	${GSTREAMER_BASE_LIBRARIES}
)

# Compiler flags
target_compile_options(gstnalcorrupter PRIVATE
	${GSTREAMER_CFLAGS_OTHER}
	${GSTREAMER_BASE_CFLAGS_OTHER}
)

# Install the plugin to the GStreamer plugin directory
if(NOT DEFINED GST_PLUGIN_DIR)
	execute_process(
		COMMAND ${PKG_CONFIG_EXECUTABLE} --variable=pluginsdir gstreamer-1.0
		OUTPUT_VARIABLE GST_PLUGIN_DIR
		OUTPUT_STRIP_TRAILING_WHITESPACE
	)
endif()

# Fallback installation directory if pkg-config doesn't provide one
if(NOT GST_PLUGIN_DIR)
	set(GST_PLUGIN_DIR "${CMAKE_INSTALL_LIBDIR}/gstreamer-1.0")
endif()

install(TARGETS gstnalcorrupter
	LIBRARY DESTINATION ${GST_PLUGIN_DIR}
)
