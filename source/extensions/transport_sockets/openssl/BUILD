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
        ":context_lib",
        ":bssl_wrapper",
        "//include/envoy/secret:secret_callbacks_interface",
        "//include/envoy/secret:secret_provider_interface",
        "//source/common/secret:sds_api_lib",
        "//include/envoy/stats:stats_macros",
    ],
)

envoy_cc_library(
    name = "context_lib",
    srcs = [
        "context_impl.cc",
        "context_manager_impl.cc",
    ],
    hdrs = [
        "context_impl.h",
        "context_manager_impl.h",
    ],
    external_deps = [
        "abseil_synchronization",
        "openssl",
    ],
    deps = [
        ":utility_lib",
        ":bssl_wrapper",
        ":openssl_impl_lib",
        "//include/envoy/ssl:context_config_interface",
        "//include/envoy/ssl:context_interface",
        "//include/envoy/ssl:context_manager_interface",
        "//include/envoy/stats:stats_interface",
        "//include/envoy/stats:stats_macros",
        "//source/common/common:assert_lib",
        "//source/common/common:base64_lib",
        "//source/common/common:hex_lib",
        "//source/common/common:utility_lib",
        "//source/common/protobuf:utility_lib",
        "@envoy_api//envoy/admin/v2alpha:certs_cc",
    ],
)

envoy_cc_library(
    name = "utility_lib",
    srcs = ["utility.cc"],
    hdrs = ["utility.h"],
    external_deps = [
        "openssl",
    ],
    deps = [
        ":bssl_wrapper",
        ":openssl_impl_lib",
        "//source/common/common:assert_lib",
        "//source/common/common:utility_lib",
    ],
)

envoy_cc_library(
    name = "openssl_impl_lib",
    srcs = ["openssl_impl.cc"],
    hdrs = ["openssl_impl.h"],
    external_deps = [
        "openssl",
    ],
    deps = [
        ":bssl_wrapper",
    ],
)


envoy_cc_library(
    name = "bssl_wrapper",
    srcs = [
        "bssl_wrapper.cc",
    ],
    hdrs = [
        "bssl_wrapper.h",
    ],
    external_deps = [
        "openssl",
    ],
)


