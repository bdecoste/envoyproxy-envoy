licenses(["notice"])  # Apache 2

# ALTS transport socket. This provides Google's ALTS protocol support in GCP to Envoy.
# https://cloud.google.com/security/encryption-in-transit/application-layer-transport-security/

load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_package",
)

envoy_package()

envoy_cc_library(
    name = "config",
    srcs = [
        "config.cc",
    ],
    hdrs = [
        "config.h",
    ],
    deps = [
        ":openssl_socket",
        "//include/envoy/registry",
        "//include/envoy/server:transport_socket_config_interface",
        "//source/extensions/transport_sockets:well_known_names",
        "@envoy_api//envoy/config/transport_socket/openssl/v2alpha:openssl_cc",
    ],
)

envoy_cc_library(
    name = "openssl_socket",
    srcs = [
        "openssl_socket.cc",
    ],
    hdrs = [
        "openssl_socket.h",
    ],
    deps = [
        "//include/envoy/network:transport_socket_interface",
        "//include/envoy/ssl:context_config_interface",
        "//source/common/buffer:buffer_lib",
        "//source/common/common:cleanup_lib",
        "//source/common/common:empty_string",
        "//source/common/common:enum_to_int",
        "//source/common/network:raw_buffer_socket_lib",
        "//source/common/protobuf:utility_lib",
        "//source/common/ssl:context_lib",
        "//include/envoy/secret:secret_callbacks_interface",
        "//include/envoy/secret:secret_provider_interface",
        "//source/common/secret:sds_api_lib",
        "//include/envoy/stats:stats_macros",
    ],
)

