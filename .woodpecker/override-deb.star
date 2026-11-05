# Debian package build, replacing the project's own CI configs on this packaging branch: builds the
# package for each of `arches` and uploads the results to builds.session.codes.
#
# The session-packaging tools read the plain assignments below (distro, builder_image, repo_suffix,
# arches), so keep them on single lines in this form.

distro = "forky"
distro_name = "Debian " + distro
builder_image = "registry.session.codes/debian-" + distro + "-builder"

# Which deb.session.foundation repo Session dependencies come from: "" (public), "/beta" or
# "/staging".
repo_suffix = "/staging"

arches = ["amd64", "i386", "arm64", "armhf"]

# Entries of skip_submodules (below) that this distro needs cloned after all, because its system
# package is missing or too old.
keep_submodules = []

# Debian architecture -> the agent platform it builds on, and its builder image's suffix.
builders = {
    "amd64": ("amd64", ""),
    "i386": ("amd64", "/i386"),
    "arm64": ("arm64", "/arm64v8"),
    "armhf": ("arm64", "/arm32v7"),
}

# Parallel build jobs, by agent platform.
jobs = {"amd64": 6, "arm64": 4}

# Extra agent labels, by agent platform: {"arm64": {"mem8": "yes"}} sends the arm64 builds to the 8GB
# agents rather than possibly a 4GB one, for builds that need the memory.
agent_labels = {"arm64": {"mem8": "yes"}}

# Submodules (by *name*, which can differ from the path) that the recursive submodule checkout
# skips.  The setting applies at every nesting level, so the names must not collide with a submodule
# we do need anywhere in the tree.
skip_submodules = [
    # Must come from the system packages: leaving the submodule empty makes a fallback to the
    # bundled copy fail instead of silently building it (see -DSUBMODULE_CHECK=OFF in debian/rules).
    "vendors/oxen-mq",
    "external/oxen-encoding",  # inside oxen-libquic
    "vendors/nlohmann_json",
    "vendors/CLI11",
    "fmt",  # inside oxen-libquic's oxen-logging
    "spdlog",
    # uWebSockets' and uSockets' test data, fuzzers, and alternative TLS/QUIC/zlib stacks, none of
    # which the build uses, and which are most of the download.
    "fuzzing/libEpollFuzzer",
    "fuzzing/seed-corpus",
    "h1spec",
    "libdeflate",
    "boringssl",
    "lsquic",
    # Test suites (BUILD_TESTS is off) and session-deps' iOS toolchain.
    "unit_test/Catch2",
    "tests/Catch2",
    "tests/CLI11",
    "googletest",
    "external/ios-cmake",
]

git_image = "docker.io/woodpeckerci/plugin-git:2"

# The default clone checks out every submodule, so clone without them and let the submodules step
# check out only the ones we need.
clone = [{
    "name": "clone",
    "image": git_image,
    "settings": {"recursive": False},
}]

submodules = {
    "name": "submodules",
    "image": git_image,
    "commands": [
        "git " + " ".join([
            "-c submodule." + s + ".update=none"
            for s in skip_submodules
            if s not in keep_submodules
        ]) + " submodule update --init --recursive --depth=1 --jobs=4",
    ],
}

apt_get = "apt-get -o=Dpkg::Use-Pty=0 -q"

session_sources = "\n".join([
    "Types: deb",
    "URIs: https://deb.session.foundation" + repo_suffix,
    "Suites: " + distro,
    "Components: main",
    "Signed-By: /usr/share/keyrings/session-foundation.gpg",
])

def deb(arch):
    platform, image_suffix = builders[arch]
    image = builder_image + image_suffix
    return {
        "name": "%s (%s)" % (distro_name, arch),
        "labels": dict({"platform": "linux/" + platform, "backend": "docker"}, **agent_labels.get(platform, {})),
        "when": [{"event": ["push", "manual"]}],
        "clone": clone,
        "steps": [
            submodules,
            {
                "name": "build",
                "image": image,
                "pull": True,
                "commands": [
                    'echo "Building on $${CI_MACHINE}"',
                    'echo "man-db man-db/auto-update boolean false" | debconf-set-selections',
                    "cp contrib/deb.session.foundation.gpg /usr/share/keyrings/session-foundation.gpg",
                    "echo '%s' >/etc/apt/sources.list.d/session.sources" % session_sources,
                    apt_get + " update",
                    apt_get + " install -y eatmydata",
                    "eatmydata " + apt_get + " dist-upgrade -y",
                    "eatmydata " + apt_get + " install --no-install-recommends -y git-buildpackage devscripts equivs g++ ccache",
                    "eatmydata dpkg-reconfigure ccache",
                    "cd debian",
                    'eatmydata mk-build-deps -i -r --tool="' + apt_get + ' -o Debug::pkgProblemResolver=yes --no-install-recommends -y" control',
                    "cd ..",
                    "eatmydata gbp buildpackage --git-no-pbuilder --git-builder='debuild --prepend-path=/usr/lib/ccache --preserve-envvar=CCACHE_*' --git-upstream-tag=HEAD -us -uc -j%d" % jobs[platform],
                ],
            },
            {
                # Kept out of the build step so that the upstream build never sees the key.
                "name": "upload",
                "image": image,
                "environment": {"SSH_KEY": {"from_secret": "SSH_KEY"}},
                "commands": [
                    apt_get + " update",
                    apt_get + " install --no-install-recommends -y openssh-client",
                    "./debian/ci-upload.sh %s %s" % (distro, arch),
                ],
            },
        ],
    }

def main(ctx):
    return [deb(arch) for arch in arches]
