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

%global _performance_build 1

Summary:              FIPS module for OpenSSL
Name:                 openssl-fips-provider
Version:              3.0.7
Release:              2%{?dist}.openela.0.1

# We have to remove certain patented algorithms from the openssl source
# tarball with the hobble-openssl script which is included below.
# The original openssl upstream tarball cannot be shipped in the .src.rpm.
Source:               openssl-%{version}-hobbled.tar.gz
Source1:              hobble-openssl
Source2:              Makefile.certificate
Source3:              genpatches
Source6:              make-dummy-cert
Source7:              renew-dummy-cert
Source9:              configuration-switch.h
Source10:             configuration-prefix.h
Source12:             ec_curve.c
Source13:             ectest.c
Source14:             0025-for-tests.patch
Source15:             fips_module-3.0.7-18.el9_2.tar.gz

# Patches exported from source git
# Aarch64 and ppc64le use lib64
Patch1:               0001-Aarch64-and-ppc64le-use-lib64.patch
# Use more general default values in openssl.cnf
Patch2:               0002-Use-more-general-default-values-in-openssl.cnf.patch
# Do not install html docs
Patch3:               0003-Do-not-install-html-docs.patch
# Override default paths for the CA directory tree
Patch4:               0004-Override-default-paths-for-the-CA-directory-tree.patch
# apps/ca: fix md option help text
Patch5:               0005-apps-ca-fix-md-option-help-text.patch
# Disable signature verification with totally unsafe hash algorithms
Patch6:               0006-Disable-signature-verification-with-totally-unsafe-h.patch
# Add support for PROFILE=SYSTEM system default cipherlist
Patch7:               0007-Add-support-for-PROFILE-SYSTEM-system-default-cipher.patch
# Add FIPS_mode() compatibility macro
Patch8:               0008-Add-FIPS_mode-compatibility-macro.patch
# Add check to see if fips flag is enabled in kernel
Patch9:               0009-Add-Kernel-FIPS-mode-flag-support.patch
# remove unsupported EC curves
Patch11:              0011-Remove-EC-curves.patch
# Disable explicit EC curves
# https://bugzilla.redhat.com/show_bug.cgi?id=2066412
Patch12:              0012-Disable-explicit-ec.patch
# Instructions to load legacy provider in openssl.cnf
Patch24:              0024-load-legacy-prov.patch
# Tmp: test name change
Patch31:              0031-tmp-Fix-test-names.patch
# We load FIPS provider and set FIPS properties implicitly
Patch32:              0032-Force-fips.patch
# Embed HMAC into the fips.so
Patch33:              0033-FIPS-embed-hmac.patch
# Comment out fipsinstall command-line utility
Patch34:              0034.fipsinstall_disable.patch
# Skip unavailable algorithms running `openssl speed`
Patch35:              0035-speed-skip-unavailable-dgst.patch
# Extra public/private key checks required by FIPS-140-3
Patch44:              0044-FIPS-140-3-keychecks.patch
# Minimize fips services
Patch45:              0045-FIPS-services-minimize.patch
# Execute KATS before HMAC verification
Patch47:              0047-FIPS-early-KATS.patch
# Selectively disallow SHA1 signatures
Patch49:              0049-Selectively-disallow-SHA1-signatures.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2049265
Patch50:              0050-FIPS-enable-pkcs12-mac.patch
# Backport of patch for RHEL for Edge rhbz #2027261
Patch51:              0051-Support-different-R_BITS-lengths-for-KBKDF.patch
# Allow SHA1 in seclevel 2 if rh-allow-sha1-signatures = yes
Patch52:              0052-Allow-SHA1-in-seclevel-2-if-rh-allow-sha1-signatures.patch
# Originally from https://github.com/openssl/openssl/pull/18103
# As we rebased to 3.0.7 and used the version of the function
# not matching the upstream one, we have to use aliasing.
# When we eliminate this patch, the `-Wl,--allow-multiple-definition`
# should also be removed
Patch56:              0056-strcasecmp.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2053289
Patch58:              0058-FIPS-limit-rsa-encrypt.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2069235
Patch60:              0060-FIPS-KAT-signature-tests.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2087147
Patch61:              0061-Deny-SHA-1-signature-verification-in-FIPS-provider.patch
Patch62:              0062-fips-Expose-a-FIPS-indicator.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2130708
# https://github.com/openssl/openssl/pull/18883
Patch67:              0067-ppc64le-Montgomery-multiply.patch
# https://github.com/openssl/openssl/commit/44a563dde1584cd9284e80b6e45ee5019be8d36c
# https://github.com/openssl/openssl/commit/345c99b6654b8313c792d54f829943068911ddbd
Patch71:              0071-AES-GCM-performance-optimization.patch
# https://github.com/openssl/openssl/commit/f596bbe4da779b56eea34d96168b557d78e1149
# https://github.com/openssl/openssl/commit/7e1f3ffcc5bc15fb9a12b9e3bb202f544c6ed5aa
# hunks in crypto/ppccap.c from https://github.com/openssl/openssl/commit/f5485b97b6c9977c0d39c7669b9f97a879312447
Patch72:              0072-ChaCha20-performance-optimizations-for-ppc64le.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2102535
Patch73:              0073-FIPS-Use-OAEP-in-KATs-support-fixed-OAEP-seed.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2102535
Patch74:              0074-FIPS-Use-digest_sign-digest_verify-in-self-test.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2102535
Patch75:              0075-FIPS-Use-FFDHE2048-in-self-test.patch
# Downstream only. Reseed DRBG using getrandom(GRND_RANDOM)
# https://bugzilla.redhat.com/show_bug.cgi?id=2102541
Patch76:              0076-FIPS-140-3-DRBG.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2102542
Patch77:              0077-FIPS-140-3-zeroization.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2114772
# https://bugzilla.redhat.com/show_bug.cgi?id=2141695
# https://bugzilla.redhat.com/show_bug.cgi?id=2160733
# https://bugzilla.redhat.com/show_bug.cgi?id=2164763
Patch78:              0078-KDF-Add-FIPS-indicators.patch
#https://bugzilla.redhat.com/show_bug.cgi?id=2141748
Patch80:              0080-rand-Forbid-truncated-hashes-SHA-3-in-FIPS-prov.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2142131
Patch81:              0081-signature-Remove-X9.31-padding-from-FIPS-prov.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2136250
Patch83:              0083-hmac-Add-explicit-FIPS-indicator-for-key-length.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2137557
Patch84:              0084-pbkdf2-Set-minimum-password-length-of-8-bytes.patch
#https://bugzilla.redhat.com/show_bug.cgi?id=2142121
Patch85:              0085-FIPS-RSA-disable-shake.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2142087
Patch88:              0088-signature-Add-indicator-for-PSS-salt-length.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2142087
Patch89:              0089-PSS-salt-length-from-provider.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2142087
Patch90:              0090-signature-Clamp-PSS-salt-len-to-MD-len.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2144561
Patch91:              0091-FIPS-RSA-encapsulate.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2142517
Patch92:              0092-provider-improvements.patch
# FIPS-95
Patch93:              0093-DH-Disable-FIPS-186-4-type-parameters-in-FIPS-mode.patch

# OpenSSL 3.0.8 CVEs
Patch101:             0101-CVE-2022-4203-nc-match.patch
Patch102:             0102-CVE-2022-4304-RSA-time-oracle.patch
Patch103:             0103-CVE-2022-4450-pem-read-bio.patch
Patch104:             0104-CVE-2023-0215-UAF-bio.patch
Patch105:             0105-CVE-2023-0216-pkcs7-deref.patch
Patch106:             0106-CVE-2023-0217-dsa.patch
Patch107:             0107-CVE-2023-0286-X400.patch
Patch108:             0108-CVE-2023-0401-pkcs7-md.patch

# https://bugzilla.redhat.com/show_bug.cgi?id=2169314
Patch109:             0109-fips-Zeroize-out-in-fips-selftest.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2168289
Patch110:             0110-GCM-Implement-explicit-FIPS-indicator-for-IV-gen.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2175145
Patch111:             0111-fips-Use-salt-16-bytes-in-PBKDF2-selftest.patch
Patch112:             0112-pbdkf2-Set-indicator-if-pkcs5-param-disabled-checks.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2179331
Patch113:             0113-asymciphers-kem-Add-explicit-FIPS-indicator.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=2157951
Patch114:             0114-FIPS-enforce-EMS-support.patch

# X.509 policies minor CVEs
Patch115:             0115-CVE-2023-0464.patch
Patch116:             0116-CVE-2023-0465.patch
Patch117:             0117-CVE-2023-0466.patch
# AES-XTS CVE
Patch118:             0118-CVE-2023-1255.patch
#https://github.com/openssl/openssl/pull/13817
#https://bugzilla.redhat.com/show_bug.cgi?id=2153471
Patch120:             0120-RSA-PKCS15-implicit-rejection.patch
# ASN.1 OID parse CVE
Patch122:             0122-CVE-2023-2650.patch
# https://github.com/openssl/openssl/pull/19386
Patch123:             0123-ibmca-atexit-crash.patch
Patch128:             0128-CVE-2023-5363.patch
# https://github.com/openssl/openssl/pull/22403
Patch129:             0129-rsa-Add-SP800-56Br2-6.4.1.2.1-3.c-check.patch
Patch130:             0001-remove-rhel-reference.patch

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
Requires:             coreutils
Conflicts:            openssl-libs < 1:3.0.7-26

%description
This package provides a custom build of the OpenSSL FIPS module that has been
submitted to NIST for certification.

%prep
%autosetup -S git -n openssl-%{version}

# The hobble_openssl is called here redundantly, just to be sure.
# The tarball has already the sources removed.
%{SOURCE1} > /dev/null

cp %{SOURCE12} crypto/ec/
cp %{SOURCE13} test/
tar xf %{SOURCE15}

## NOTE: we do a full build every time to endure our ability to build
## from source as needed, but in RHEL we ultimately throw away all
## binaries and replace with the certified one.
%build
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

%define fips %{version}-395c1a240fbfffd8
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

%check
#We re not using the actual built bits, so skip any checks on those binaries.


# Replace the binary after all debugging info is extracted so we can ship
# working debuginfo files
%define __spec_install_post \
    %{?__debug_package:%{__debug_install_post}} \
    %{__arch_install_post} \
    %{__os_install_post} \
    cp fips_module/fips.so.%{_arch} $RPM_BUILD_ROOT%{_libdir}/ossl-modules/fips.so \
%{nil}

%define __provides_exclude_from %{_libdir}/openssl

%install
install -d $RPM_BUILD_ROOT{%{_bindir},%{_includedir},%{_libdir},%{_mandir},%{_libdir}/openssl,%{_pkgdocdir}}
%make_install
rm -fr $RPM_BUILD_ROOT%{_bindir}
rm -fr $RPM_BUILD_ROOT%{_includedir}
rm -fr $RPM_BUILD_ROOT%{_libdir}/engines-3
rm -fr $RPM_BUILD_ROOT%{_libdir}/libcrypto.*
rm -fr $RPM_BUILD_ROOT%{_libdir}/libssl.*
rm -fr $RPM_BUILD_ROOT%{_libdir}/openssl
rm -fr $RPM_BUILD_ROOT%{_libdir}/ossl-modules/legacy.so
rm -fr $RPM_BUILD_ROOT%{_libdir}/pkgconfig
rm -fr $RPM_BUILD_ROOT%{_mandir}
rm -fr $RPM_BUILD_ROOT%{_pkgdocdir}
rm -fr $RPM_BUILD_ROOT%{_sysconfdir}

%files
%attr(0755,root,root) %{_libdir}/ossl-modules/fips.so

%changelog
* Tue Apr 30 2024 Release Engineering <releng@openela.org> - 3.0.7.openela.0.1
- Add OpenELA specific changes

* Wed Feb 21 2024 Dmitry Belyavskiy <dbelyavs@redhat.com> - 3.0.7-2
- Denote conflict with old versions of openssl-libs package
  Related: RHEL-23474

* Wed Jan 24 2024 Simo Sorce <ssorce@redhat.com> - 3.0.7-1
Initial packaging
