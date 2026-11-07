# Linux builds, run in our Debian/Ubuntu images on the docker agents.

registry = "registry.session.codes/"

events = ["push", "pull_request", "tag", "manual"]

apt_get = "apt-get -o=Dpkg::Use-Pty=0 -q"

lib_deps = [
    "autoconf",
    "libboost-program-options-dev",
    # Must be the gnutls flavour, not libcurl4-openssl-dev: that one pulls in
    # libngtcp2_crypto_ossl, whose symbols are identical to libngtcp2_crypto_gnutls's, so whichever
    # of the two the loader reaches first satisfies *both* libcurl and liboxenquic.  When ossl wins,
    # libquic hands a gnutls_session_t to SSL_do_handshake() and the process segfaults.  The gnutls
    # build of libcurl uses the same ngtcp2 backend (and the same gnutls) that libquic does.
    "libcurl4-gnutls-dev",
    "libevent-dev",
    "libjemalloc-dev",
    "libsodium-dev",
    "libgnutls28-dev",
    "libsqlite3-dev",
    "libssl-dev",
    "libsystemd-dev",
    "libngtcp2-dev",
    "libngtcp2-crypto-gnutls-dev",
    "libzmq3-dev",
    "make",
    "pkg-config",
]

# USE_LTO is given either way because it defaults to on.
default_cmake = {
    "CMAKE_BUILD_TYPE": "Release",
    "CMAKE_CXX_FLAGS": "-fdiagnostics-color=always",
    "LOCAL_MIRROR": "https://builds.session.codes/deps",
    "EXTRA_WARNINGS": True,
    "WARNINGS_AS_ERRORS": True,
    "BUILD_TESTS": True,
    "USE_LTO": False,
}

def cmake_args(opts):
    return " ".join([
        "-D%s=%s" % (k, ("ON" if v else "OFF") if type(v) == "bool" else v)
        for k, v in opts.items()
    ])

# The build needs tags (for the version and archive names), and fetches submodules itself.
clone = [{
    "name": "clone",
    "image": "docker.io/woodpeckerci/plugin-git:2",
    "settings": {"tags": True, "recursive": False},
}]

submodules = {
    "name": "submodules",
    "image": "docker.io/woodpeckerci/plugin-git:2",
    "commands": [
        # uWebSockets includes nearly 900MB of submodules that we don't use, so check out only the
        # parts of it that we do.
        "git submodule update --init --depth=1 external/uWebSockets",
        "cd external/uWebSockets",
        "git rm fuzzing/seed-corpus",
        "git submodule update --init --depth=1 uSockets",
        "cd uSockets",
        "git rm boringssl lsquic",
        "cd ../../..",
        "git submodule update --init --recursive --depth=1 --jobs=4",
    ],
}

def workflow(name, labels, steps):
    return {
        "name": name,
        "labels": labels,
        "when": [{"event": events}],
        "clone": clone,
        "steps": steps,
    }

session_repo = [
    "eatmydata " + apt_get + " install --no-install-recommends -y lsb-release",
    "cp contrib/deb.session.foundation.gpg /etc/apt/trusted.gpg.d",
    "echo deb http://deb.session.foundation $$(lsb_release -sc) main >/etc/apt/sources.list.d/session.list",
    "eatmydata " + apt_get + " update",
]

# `package` is the commands, run in build/ after the tests, that make the files to upload; a build
# given them also gets the upload step.
def linux(
        name,
        image,
        arch = "amd64",
        deps = ["g++"] + lib_deps,
        setup = [],
        cmake = {},
        jobs = 6,
        package = []):
    opts = dict(default_cmake)
    opts.update(cmake)
    steps = [submodules, {
        "name": "build",
        "image": registry + image,
        "pull": True,
        "commands": [
            'echo "Building on $${CI_MACHINE}"',
            'echo "man-db man-db/auto-update boolean false" | debconf-set-selections',
            apt_get + " update",
            apt_get + " install -y eatmydata",
        ] + setup + [
            "eatmydata " + apt_get + " dist-upgrade -y",
            "eatmydata " + apt_get + " install -y --no-install-recommends " +
            " ".join(["cmake", "git", "ca-certificates", "ninja-build", "ccache"] + deps),
            "mkdir build",
            "cd build",
            "cmake .. -G Ninja " + cmake_args(opts),
            "ninja -j%d -v" % jobs,
            "./oxen-storage --version",
            "./unit_test/Test",
        ] + package,
    }]
    if package:
        steps.append({
            "name": "upload",
            "image": registry + image,
            "environment": {"SSH_KEY": {"from_secret": "SSH_KEY"}},
            "commands": [
                apt_get + " update",
                apt_get + " install -y --no-install-recommends openssh-client",
                "cd build",
                "../contrib/ci-static-upload.sh",
            ],
            "when": [{"event": ["push", "tag"], "repo": "session-foundation/*"}],
        })
    return workflow(name, {"platform": "linux/" + arch, "backend": "docker"}, steps)

def clang(version):
    return linux(
        "Debian sid: clang-%d (amd64)" % version,
        "debian-sid-clang",
        deps = ["clang-%d" % version, "clang-tools-%d" % version] + lib_deps,
        cmake = {
            "CMAKE_C_COMPILER": "clang-%d" % version,
            "CMAKE_CXX_COMPILER": "clang++-%d" % version,
            "USE_LTO": True,
        },
    )

def main(ctx):
    return [
        workflow("lint check", {"platform": "linux/amd64", "backend": "docker"}, [{
            "name": "build",
            "image": registry + "lint",
            "pull": True,
            "commands": [
                'echo "Building on $${CI_MACHINE}"',
                apt_get + " update",
                apt_get + " install -y eatmydata",
                "eatmydata " + apt_get + " install --no-install-recommends -y git clang-format-19",
                "./contrib/ci-lint-check.sh",
            ],
        }]),

        linux("Debian (amd64)", "debian-sid", cmake = {"USE_LTO": True}),
        linux("Debian Debug (amd64)", "debian-sid", cmake = {"CMAKE_BUILD_TYPE": "Debug"}),
        clang(19),
        linux("Debian stable (i386)", "debian-stable/i386", cmake = {"WARNINGS_AS_ERRORS": False}),
        linux("Ubuntu LTS (amd64)", "ubuntu-lts", setup = session_repo),
        linux("Ubuntu latest (amd64)", "ubuntu-rolling"),
        linux("Debian 12 bookworm (amd64)", "debian-bookworm", setup = session_repo),

        # The default build is uWebSockets only.  These keep the libmicrohttpd backend compiling,
        # alone and alongside uWebSockets, so that it stays usable for comparison.
        linux(
            "Debian sid, MHD-only (amd64)",
            "debian-sid",
            cmake = {"HTTPS_BACKEND_UWEBSOCKETS": False, "HTTPS_BACKEND_MICROHTTPD": True},
        ),
        linux("Debian sid, uWS+MHD (amd64)", "debian-sid", cmake = {"HTTPS_BACKEND_MICROHTTPD": True}),

        # ARM builds; armhf builds in a 32-bit image on the arm64 agents.  The ARM box is shared and
        # short on RAM: at the default -j6 it kills compilers mid-build.
        linux("Debian sid (ARM64)", "debian-sid", arch = "arm64", jobs = 4),
        linux(
            "Debian stable (armhf)",
            "debian-stable/arm32v7",
            arch = "arm64",
            jobs = 4,
            cmake = {"WARNINGS_AS_ERRORS": False},
        ),

        # The static build is uploaded to builds.session.codes.
        linux(
            "Static (jammy amd64)",
            "ubuntu-jammy",
            deps = ["autoconf", "automake", "file", "g++", "libtool", "make", "patch", "pkg-config"],
            cmake = {"BUILD_STATIC_DEPS": True, "USE_LTO": True},
            package = ["../contrib/ci-check-static-libs.sh", "ninja strip", "ninja create_tarxz"],
        ),
    ]
