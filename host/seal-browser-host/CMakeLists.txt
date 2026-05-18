# seal-browser-host - standalone native messaging stdio <-> named-pipe bridge.
#
# Tiny C++ executable launched by the browser when the WebExtension calls
# connectNative(). Forwards length-prefixed JSON between Chrome's
# native-messaging protocol (stdin/stdout) and the seal named pipe.
#
# Built as a separate target so it can be signed independently and
# packaged alongside seal.exe.

add_executable(seal_browser_host
    main.cpp
)

set_target_properties(seal_browser_host PROPERTIES
    OUTPUT_NAME "seal-browser-host"
    # Match the parent's runtime output directory so installers find both
    # exes in the same place.
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}"
)

target_compile_definitions(seal_browser_host PRIVATE
    NOMINMAX
    _WIN32_WINNT=0x0A00
)

# Console subsystem (the browser pipes stdin/stdout; we need a console
# entry point, not WinMain).
if(MSVC)
    set_target_properties(seal_browser_host PROPERTIES
        LINK_FLAGS "/SUBSYSTEM:CONSOLE /ENTRY:wmainCRTStartup"
    )
endif()

install(TARGETS seal_browser_host
    RUNTIME DESTINATION bin
)
