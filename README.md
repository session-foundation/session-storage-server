# Oxen Storage Server

Storage server for Oxen Service Nodes

## Binary releases

Pre-built releases (with system service files) are available for Ubuntu/Debian on
https://deb.oxen.io and are recommended for simple deployment and updates on those distributions.

## Building from source

The default build compiles for the current system and requires the following be installed (including
headers/dev packages for the libraries):

Requirements:
* a C++20 compiler
* cmake >= 3.18
* pkg-config (any version)

These are used from the system when a new enough version is installed, and otherwise downloaded and
built statically as part of the build:
* libmicrohttpd >= 1.0.8 (only for the libmicrohttpd HTTPS backend; the floor is a security fix
  level, not an API one, so most distro packages are currently too old and it gets built statically)
* libsodium >= 1.0.18
* libcurl >= 7.68
* libevent >= 2.1
* libzmq >= 4.3
* sqlite >= 3.35.5
* gnutls and ngtcp2 (required by oxen-libquic)

The uWebSockets HTTPS backend (see below) additionally needs OpenSSL >= 3, which must come from the
system: it is never built as part of the build, and that backend cannot be part of a
`BUILD_STATIC_DEPS` build.

These are used from the system if found, and otherwise built from the bundled submodules:
* oxen-libquic >= 1.9
* oxen-mq >= 1.3
* oxen-encoding >= 1.5
* nlohmann-json >= 3.11
* CLI11 >= 2.2

jemalloc is linked against when it is found; it isn't required, but is recommended for reduced
long-term memory use.

You can instruct the build to ignore system libraries entirely and download and build static
versions of everything by adding the `-D BUILD_STATIC_DEPS=ON` option to the `cmake` command below.
That additionally requires autoconf, automake, libtool and patch, and will result in a slower build
and a larger, slower binary, as is typical for static builds.

```
git submodule update --init --recursive
cmake -B build -S .. -D CMAKE_BUILD_TYPE=Release -G Ninja
cmake --build build --parallel
```

The build will produce a `./build/oxen-storage` binary.  You can run it with `--help` to
see supported run-time options.

## HTTPS backends

The HTTPS listener has two interchangeable implementations: one on libmicrohttpd (GnuTLS, which the
rest of the program already uses) and the previous one on uWebSockets (which brings in the system's
OpenSSL).  By default only libmicrohttpd is built, and the resulting binary has no OpenSSL
dependency.  The
uWebSockets backend can be added with `-D HTTPS_BACKEND_UWEBSOCKETS=ON` (or built alone, with
`-D HTTPS_BACKEND_MICROHTTPD=OFF` as well); when both are present, `--https-backend
uwebsockets|microhttpd` selects one at startup, defaulting to `microhttpd`.

# Running

Oxen Storage Server is a required component of an Oxen Service Node and needs to talk to a running
`oxend` in order to join the network.  The program defaults are designed to work with a default
oxend, but for advanced configurations (e.g. to run on different ports) you may need to use other
options.  Run the program with `--help` to see all available options.

See https://docs.oxen.io/ for additional details on setting up and running an Oxen Service Node.
