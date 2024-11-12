# For the curious:
# 0.9.8jk + EAP-FAST soversion = 8
# 1.0.0 soversion = 10
# 1.1.0 soversion = 1.1 (same as upstream although presence of some symbols
#                        depends on build configuration options)
# 3.0.0 soversion = 3 (same as upstream)
%define soversion 3

# Arches on which we need to prevent arch conflicts on opensslconf.h, must
# also be handled in opensslconf-new.h.
%define multilib_arches %{ix86} ia64 %{mips} ppc ppc64 s390 s390x sparcv9 sparc64 x86_64

%global debug_package %{nil}
%define orig_release 18.el9_2

Summary:              FIPS module for OpenSSL
Name:                 openssl-fips-provider
Version:              3.0.7
Release:              6%{?dist}.openela.0.1

# We have to remove certain patented algorithms from the openssl source
# tarball with the hobble-openssl script which is included below.
# The original openssl upstream tarball cannot be shipped in the .src.rpm.
Source:               %{name}-%{version}.tar.gz
Source1:              extract-src.sh
Source2:              extract-fips.sh
Source3:              README.md

Patch1:               0001-remove-rhel-reference.patch

License:              ASL 2.0
URL:                  http://www.openssl.org/
BuildRequires:        gcc g++
BuildRequires:        coreutils, perl-interpreter, sed, zlib-devel, /usr/bin/cmp
BuildRequires:        lksctp-tools-devel
BuildRequires:        /usr/bin/rename
BuildRequires:        /usr/bin/pod2man
BuildRequires:        /usr/sbin/sysctl
BuildRequires:        perl(Test::Harness), perl(Test::More), perl(Math::BigInt)
BuildRequires:        perl(Module::Load::Conditional), perl(File::Temp)
BuildRequires:        perl(Time::HiRes), perl(IPC::Cmd), perl(Pod::Html), perl(Digest::SHA)
BuildRequires:        perl(FindBin), perl(lib), perl(File::Compare), perl(File::Copy), perl(bigint)
BuildRequires:        git-core
Requires:             %{name}-so = %{version}-%{release}

%description
This package provides a custom build of the OpenSSL FIPS module that has been
submitted to NIST for certification.

%files
%doc README.md

%package so
Summary:              FIPS module for OpenSSL
Requires:             coreutils
Conflicts:            openssl-libs < 1:3.0.7-26
Obsoletes:            openssl-fips-provider < 3.0.7-3

%description so
This package provides a custom build of the OpenSSL FIPS module that has been
submitted to NIST for certification.

%files so
%attr(0755,root,root) %{_libdir}/ossl-modules/fips.so

%package so-debuginfo
Summary:              Debug information for package %{name}
Group:                Development/Debug
Recommends:           %{name}-so-debugsource = %{version}-%{release}
%description so-debuginfo
This package provides debug information for package %{name}.
Debug information is useful when developing applications that use this
package or when debugging this package.
%files so-debuginfo -f debuginfo.list

%package so-debugsource
Summary:              Debug sources for package %{name}
Group:                Development/Debug
%description so-debugsource
This package provides debug sources for package %{name}.
Debug sources are useful when developing applications that use this
package or when debugging this package.
%files so-debugsource -f debugsourcefiles.list

%prep
tar xf %{SOURCE0}
%{SOURCE1} %{version} %{orig_release}

## NOTE: we do a full build every time to endure our ability to build
## from source as needed, but in RHEL we ultimately throw away all
## binaries and replace with the certified one.
%build
pushd openssl-%{version}
# Figure out which flags we want to use.
# default
sslarch=%{_os}-%{_target_cpu}
%ifarch %ix86
sslarch=linux-elf
if ! echo %{_target} | grep -q i686 ; then
	sslflags="no-asm 386"
fi
%endif
%ifarch x86_64
sslflags=enable-ec_nistp_64_gcc_128
%endif
%ifarch sparcv9
sslarch=linux-sparcv9
sslflags=no-asm
%endif
%ifarch sparc64
sslarch=linux64-sparcv9
sslflags=no-asm
%endif
%ifarch alpha alphaev56 alphaev6 alphaev67
sslarch=linux-alpha-gcc
%endif
%ifarch s390 sh3eb sh4eb
sslarch="linux-generic32 -DB_ENDIAN"
%endif
%ifarch s390x
sslarch="linux64-s390x"
%endif
%ifarch %{arm}
sslarch=linux-armv4
%endif
%ifarch aarch64
sslarch=linux-aarch64
sslflags=enable-ec_nistp_64_gcc_128
%endif
%ifarch sh3 sh4
sslarch=linux-generic32
%endif
%ifarch ppc64 ppc64p7
sslarch=linux-ppc64
%endif
%ifarch ppc64le
sslarch="linux-ppc64le"
sslflags=enable-ec_nistp_64_gcc_128
%endif
%ifarch mips mipsel
sslarch="linux-mips32 -mips32r2"
%endif
%ifarch mips64 mips64el
sslarch="linux64-mips64 -mips64r2"
%endif
%ifarch mips64el
sslflags=enable-ec_nistp_64_gcc_128
%endif
%ifarch riscv64
sslarch=linux-generic64
%endif

# Add -Wa,--noexecstack here so that libcrypto's assembler modules will be
# marked as not requiring an executable stack.
# Also add -DPURIFY to make using valgrind with openssl easier as we do not
# want to depend on the uninitialized memory as a source of entropy anyway.
RPM_OPT_FLAGS="$RPM_OPT_FLAGS -Wa,--noexecstack -Wa,--generate-missing-build-notes=yes -DPURIFY $RPM_LD_FLAGS"

export HASHBANGPERL=/usr/bin/perl

%define fips %{version}-nevership
# ia64, x86_64, ppc are OK by default
# Configure the build tree.  Override OpenSSL defaults with known-good defaults
# usable on all platforms.  The Configure script already knows to use -fPIC and
# RPM_OPT_FLAGS, so we can skip specifiying them here.
./Configure \
	--prefix=%{_prefix} --openssldir=%{_sysconfdir}/pki/tls ${sslflags} \
	--system-ciphers-file=%{_sysconfdir}/crypto-policies/back-ends/openssl.config \
	zlib enable-camellia enable-seed enable-rfc3779 enable-sctp \
	enable-cms enable-md2 enable-rc5 enable-ktls enable-fips\
	no-mdc2 no-ec2m no-sm2 no-sm4 enable-buildtest-c++\
	shared  ${sslarch} $RPM_OPT_FLAGS '-DDEVRANDOM="\"/dev/urandom\"" -DREDHAT_FIPS_VERSION="\"%{fips}\""'\
	-Wl,--allow-multiple-definition

# Do not run this in a production package the FIPS symbols must be patched-in
#util/mkdef.pl crypto update

make %{?_smp_mflags} all

popd

%check
#We re not using the actual built bits, so skip any checks on those binaries.

%install
#we are not actually installing the build, as we replace all contents with the
#content from the original rpms
export ORIGINAL_PACKAGE_VERSION=%{version}
export ORIGINAL_PACKAGE_RELEASE=%{orig_release}
%{SOURCE2}
install -d $RPM_BUILD_ROOT%{_pkgdocdir}
install -m644 %{SOURCE3} $RPM_BUILD_ROOT%{_pkgdocdir}/README.md

%changelog
* Tue Nov 12 2024 Release Engineering <releng@openela.org> - 3.0.7.openela.0.1
- Add OpenELA specific changes

* Tue Sep 10 2024 Simo Sorce <ssorce@redhat.com> - 3.0.7-6
- Try to fix an upgrade issue with pkg version numbers
  Resolves: RHEL-58662

* Mon Apr 29 2024 Simo Sorce <ssorce@redhat.com> - 3.0.7-5
- Add an empty metapackage and proper requires to correctly
  handle upgrades.
  Related: RHEL-32123

* Tue Apr 23 2024 Simo Sorce <ssorce@redhat.com> - 3.0.7-4
- Change subpackage names to avoid build gating issues
  Related: RHEL-32123

* Tue Apr 16 2024 Simo Sorce <ssorce@redhat.com> - 3.0.7-3
- Change tarball source contents
- Rework file extraction process
- Fixes debug packages
  Resolves: RHEL-32123

* Wed Feb 21 2024 Dmitry Belyavskiy <dbelyavs@redhat.com> - 3.0.7-2
- Denote conflict with old versions of openssl-libs package
  Related: RHEL-23474

* Wed Jan 24 2024 Simo Sorce <ssorce@redhat.com> - 3.0.7-1
Initial packaging
