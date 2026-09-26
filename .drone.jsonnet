local distro = 'sid';
local distro_name = 'Debian ' + distro;
local distro_docker = 'registry.oxen.rocks/debian-' + distro + '-builder';

local apt_get_quiet = 'apt-get -o=Dpkg::Use-Pty=0 -q';

local repo_suffix = '/staging';  // can be /beta or /staging for non-primary repo deps

// Entries of skip_submodules (below) that this distro needs cloned after all, because its system
// package is missing or too old.
local keep_submodules = [];

// Submodules (by *name*, which can differ from the path) that the recursive clone skips.  The
// setting applies at every nesting level, so the names must not collide with a submodule we do
// need anywhere in the tree.
local skip_submodules = [
  // Must come from the system packages: leaving the submodule empty makes a fallback to the bundled
  // copy fail instead of silently building it (see -DSUBMODULE_CHECK=OFF in debian/rules).
  'vendors/oxen-mq',
  'external/oxen-encoding',  // inside oxen-libquic
  'vendors/nlohmann_json',
  'vendors/CLI11',
  'fmt',  // inside oxen-libquic's oxen-logging
  'spdlog',
  // uWebSockets' and uSockets' test data, fuzzers, and alternative TLS/QUIC/zlib stacks, none of
  // which the build uses, and which are most of the download.
  'fuzzing/libEpollFuzzer',
  'fuzzing/seed-corpus',
  'h1spec',
  'libdeflate',
  'boringssl',
  'lsquic',
  // Test suites (BUILD_TESTS is off) and session-deps' iOS toolchain.
  'unit_test/Catch2',
  'tests/Catch2',
  'tests/CLI11',
  'googletest',
  'external/ios-cmake',
];
local submodules = {
  name: 'submodules',
  image: 'drone/git',
  commands: [
    'git fetch --tags',
    'git ' + std.join(' ', [
      '-c submodule.' + s + '.update=none'
      for s in skip_submodules
      if std.count(keep_submodules, s) == 0
    ])
    + ' submodule update --init --recursive --depth=1 --jobs=4',
  ],
};

local deb_pipeline(image, buildarch='amd64', debarch='amd64', jobs=6) = {
  kind: 'pipeline',
  type: 'docker',
  name: distro_name + ' (' + debarch + ')',
  platform: { arch: buildarch },
  steps: [
    submodules,
    {
      name: 'build',
      image: image,
      environment: { SSH_KEY: { from_secret: 'SSH_KEY' } },
      commands: [
        'echo $DRONE_STAGE_MACHINE',
        'echo "man-db man-db/auto-update boolean false" | debconf-set-selections',
        'cp contrib/deb.session.foundation.gpg /etc/apt/trusted.gpg.d/deb.session.foundation.gpg',
        'echo deb http://deb.session.foundation' + repo_suffix + ' ' + distro + ' main >/etc/apt/sources.list.d/session.list',
        apt_get_quiet + ' update',
        apt_get_quiet + ' install -y eatmydata',
        'eatmydata ' + apt_get_quiet + ' dist-upgrade -y',
        'eatmydata ' + apt_get_quiet + ' install --no-install-recommends -y git-buildpackage devscripts equivs g++ ccache openssh-client',
        'eatmydata dpkg-reconfigure ccache',
        'cd debian',
        'eatmydata mk-build-deps -i -r --tool="' + apt_get_quiet + ' -o Debug::pkgProblemResolver=yes --no-install-recommends -y" control',
        'cd ..',
        "eatmydata gbp buildpackage --git-no-pbuilder --git-builder='debuild --prepend-path=/usr/lib/ccache --preserve-envvar=CCACHE_*' --git-verbose --git-no-submodules --git-upstream-tag=HEAD -us -uc -j" + jobs,
        './debian/ci-upload.sh ' + distro + ' ' + debarch,
      ],
    },
  ],
};

[
  deb_pipeline(distro_docker),
  deb_pipeline(distro_docker + '/i386', buildarch='amd64', debarch='i386'),
  deb_pipeline(distro_docker + '/arm64v8', buildarch='arm64', debarch='arm64', jobs=1),
  deb_pipeline(distro_docker + '/arm32v7', buildarch='arm64', debarch='armhf', jobs=1),
]
