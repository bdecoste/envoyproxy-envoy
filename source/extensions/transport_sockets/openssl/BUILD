licenses(["notice"])  # Apache 2

# ALTS transport socket. This provides Google's ALTS protocol support in GCP to Envoy.
# https://cloud.google.com/security/encryption-in-transit/application-layer-transport-security/

load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_package",
)

envoy_package()

#envoy_cc_library(
#    name = "grpc_openssl_wrapper",
#    hdrs = [
#        "grpc_openssl.h",
#    ],
#    external_deps = [
#        "grpc",
#    ],
#    visibility = ["//visibility:private"],
#    deps = [
#        "//source/common/common:c_smart_ptr_lib",
#    ],
#)

envoy_cc_library(
    name = "config",
    srcs = [
        "config.cc",
    ],
    hdrs = [
        "config.h",
    ],
    deps = [
 #       ":openssl_handshaker",
        ":openssl_socket",
        "//include/envoy/registry",
        "//include/envoy/server:transport_socket_config_interface",
        "//source/extensions/transport_sockets:well_known_names",
        "@envoy_api//envoy/config/transport_socket/openssl/v2alpha:openssl_cc",
    ],
)

#envoy_cc_library(
#   name = "openssl_frame_protector",
#    srcs = [
#        "openssl_frame_protector.cc",
#    ],
#    hdrs = [
#        "openssl_frame_protector.h",
#    ],
#    deps = [
#        ":grpc_openssl_wrapper",
#        "//source/common/buffer:buffer_lib",
#    ],
#)

#envoy_cc_library(
#    name = "openssl_handshaker",
#    srcs = [
#        "openssl_handshaker.cc",
#    ],
#    hdrs = [
#        "openssl_handshaker.h",
#    ],
#    deps = [
#        ":grpc_openssl_wrapper",
#        "//include/envoy/event:dispatcher_interface",
#        "//source/common/buffer:buffer_lib",
#    ],
#)

envoy_cc_library(
    name = "openssl_socket",
    srcs = [
        "openssl_socket.cc",
    ],
    hdrs = [
        "openssl_socket.h",
    ],
    deps = [
 #       ":noop_transport_socket_callbacks_lib",
 #       ":openssl_frame_protector",
 #       ":openssl_handshaker",
 #       ":grpc_openssl_wrapper",
        "//include/envoy/network:transport_socket_interface",
        "//source/common/buffer:buffer_lib",
        "//source/common/common:cleanup_lib",
        "//source/common/common:empty_string",
        "//source/common/common:enum_to_int",
        "//source/common/network:raw_buffer_socket_lib",
        "//source/common/protobuf:utility_lib",
        "//source/common/ssl:context_lib",
    ],
)

#envoy_cc_library(
#   name = "noop_transport_socket_callbacks_lib",
#    hdrs = ["noop_transport_socket_callbacks.h"],
#    deps = ["//include/envoy/network:transport_socket_interface"],
#)
