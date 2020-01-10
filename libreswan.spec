# These are rpm macros and are 0 or 1
%global crl_fetching 1
%global _hardened_build 1
%global buildefence 0
%global development 0
%global cavstests 1

# These are libreswan/make macros and are false or true
%global USE_FIPSCHECK true
%global USE_LIBCAP_NG true
%global USE_LABELED_IPSEC true
%global USE_DNSSEC true
%global USE_NM true
%global USE_LINUX_AUDIT true
%global USE_SECCOMP true
%global NSS_HAS_IPSEC_PROFILE true

%if 0%{?fedora}
%global rhel 7
%endif

#global prever dr1

Name: libreswan
Summary: IPsec implementation with IKEv1 and IKEv2 keying protocols
Version: 3.25
Release: %{?prever:0.}8.1%{?prever:.%{prever}}%{?dist}
License: GPLv2
Group: System Environment/Daemons
Url: https://libreswan.org/
Source: https://download.libreswan.org/%{?prever:development/}%{name}-%{version}%{?prever}.tar.gz
Source1: ikev1_dsa.fax.bz2
Source2: ikev1_psk.fax.bz2
Source3: ikev2.fax.bz2

Patch1: libreswan-3.25-alg_info.patch
Patch2: libreswan-3.25-relax-delete.patch
Patch3: libreswan-3.25-EKU-1639404.patch
Patch4: libreswan-3.23-del-with-notify-1630355.patch
Patch5: libreswan-3.23-zerolengthkey.patch
Patch6: libreswan-3.25-1625303-recursive-incl.patch
Patch7: libreswan-3.25-1623279-xauth-null-pwd.patch
Patch8: libreswan-3.25-1664521-fips-keysize.patch
Patch9: libreswan-3.25-1679735-critical_flag.patch
Patch10: libreswan-3.25-1673105-down-restart.patch
Patch11: libreswan-3.25-1686991-ikev1-del.patch
Patch12: libreswan-3.25-1724200-halfopen-shunt.patch

Requires: iproute >= 2.6.8
Requires: nss-tools nss-softokn

BuildRequires: bison flex redhat-rpm-config pkgconfig
BuildRequires: nspr-devel
BuildRequires: pam-devel
BuildRequires: xmlto
# minimum nss version for IPsec profile support, see rhbz#1212132
Requires: nss >= 3.36.0-8
BuildRequires: nss-devel >= 3.36.0-8

%if %{?rhel} <= 6
BuildRequires: libevent2-devel net-tools

Requires(post): coreutils bash
Requires(preun): initscripts chkconfig
Requires(post): /sbin/chkconfig
Requires(preun): /sbin/chkconfig
Requires(preun): /sbin/service
%else
BuildRequires: libevent-devel hostname

BuildRequires: systemd-devel
Requires(post): coreutils bash systemd
Requires(preun): systemd
Requires(postun): systemd
%endif

%if %{USE_DNSSEC}
BuildRequires: ldns-devel
Requires: unbound-libs >= 1.6.6
BuildRequires: unbound-devel >= 1.6.6
%endif

%if %{USE_SECCOMP}
BuildRequires: libseccomp-devel
%endif

%if %{USE_LABELED_IPSEC}
BuildRequires: libselinux-devel
%endif

%if %{USE_FIPSCHECK}
BuildRequires: fipscheck-devel
# we need fipshmac
Requires: fipscheck%{_isa}
%endif

%if %{USE_LINUX_AUDIT}
Buildrequires: audit-libs-devel
%endif

%if %{USE_LIBCAP_NG}
BuildRequires: libcap-ng-devel
%endif

%if %{crl_fetching}
BuildRequires: openldap-devel curl-devel
%endif

%if %{buildefence}
BuildRequires: ElectricFence
%endif

Conflicts: openswan < %{version}-%{release}
Provides: openswan = %{version}-%{release}
Provides: openswan-doc = %{version}-%{release}
Obsoletes: openswan < %{version}-%{release}

%description
Libreswan is a free implementation of IPsec & IKE for Linux.  IPsec is
the Internet Protocol Security and uses strong cryptography to provide
both authentication and encryption services.  These services allow you
to build secure tunnels through untrusted networks.  Everything passing
through the untrusted net is encrypted by the ipsec gateway machine and
decrypted by the gateway at the other end of the tunnel.  The resulting
tunnel is a virtual private network or VPN.

This package contains the daemons and userland tools for setting up
Libreswan. It supports the NETKEY/XFRM IPsec kernel stack that exists
in the default Linux kernel.

Libreswan also supports IKEv2 (RFC-7296) and Secure Labeling

Libreswan is based on Openswan-2.6.38 which in turn is based on FreeS/WAN-2.04

%prep
%setup -q -n libreswan-%{version}%{?prever}
%patch1 -p1
%patch2 -p1
%patch3 -p1
%patch4 -p1
%patch5 -p1
%patch6 -p1
%patch7 -p1
%patch8 -p1
%patch9 -p1
%patch10 -p1
%patch11 -p1
%patch12 -p1

%build
%if %{buildefence}
 %define efence "-lefence"
%endif

make %{?_smp_mflags} \
%if %{development}
   USERCOMPILE="-g -DGCC_LINT %(echo %{optflags} | sed -e s/-O[0-9]*/ /) %{?efence} -fPIE -pie -fno-strict-aliasing -Wformat-nonliteral -Wformat-security" \
%else
  USERCOMPILE="-g -DGCC_LINT %{optflags} %{?efence} -fPIE -pie -fno-strict-aliasing -Wformat-nonliteral -Wformat-security" \
%endif
  USERLINK="-g -pie -Wl,-z,relro,-z,now %{?efence}" \
  INC_USRLOCAL=%{_prefix} \
  FINALLIBDIR=%{_libexecdir}/ipsec \
  FINALLIBEXECDIR=%{_libexecdir}/ipsec \
  FINALRUNDIR=%{_rundir}/pluto \
  MANTREE=%{buildroot}%{_mandir} \
  INC_RCDEFAULT=%{_initrddir} \
%if %{?rhel} <= 6
  INITSYSTEM=sysvinit \
%else
  INITSYSTEM=systemd \
%endif
  USE_NM=%{USE_NM} \
  USE_XAUTHPAM=true \
  USE_FIPSCHECK="%{USE_FIPSCHECK}" \
  USE_LIBCAP_NG="%{USE_LIBCAP_NG}" \
  USE_LABELED_IPSEC="%{USE_LABELED_IPSEC}" \
  USE_LINUX_AUDIT="%{USE_LINUX_AUDIT}" \
%if %{crl_fetching}
  USE_LDAP=true \
  USE_LIBCURL=true \
%else
  USE_LDAP=false \
  USE_LIBCURL=false \
%endif
  USE_DNSSEC="%{USE_DNSSEC}" \
  USE_SECCOMP="%{USE_SECCOMP}" \
  NSS_HAS_IPSEC_PROFILE="%{NSS_HAS_IPSEC_PROFILE}" \
  USE_DH22=true \
  programs
FS=$(pwd)

%if %{USE_FIPSCHECK}
# Add generation of HMAC checksums of the final stripped binaries
%if %{?rhel} <= 6
%define __spec_install_post \
    %{?__debug_package:%{__debug_install_post}} \
    %{__arch_install_post} \
    %{__os_install_post} \
    fipshmac %{buildroot}%{_libexecdir}/ipsec/pluto \
%{nil}
%else
%define __spec_install_post \
    %{?__debug_package:%{__debug_install_post}} \
    %{__arch_install_post} \
    %{__os_install_post} \
    mkdir -p %{buildroot}%{_libdir}/fipscheck/ \
    fipshmac -d %{buildroot}%{_libdir}/fipscheck %{buildroot}%{_libexecdir}/ipsec/pluto
%{nil}
%endif
%endif

%install
make \
  DESTDIR=%{buildroot} \
  INC_USRLOCAL=%{_prefix} \
  FINALLIBDIR=%{_libexecdir}/ipsec \
  FINALLIBEXECDIR=%{_libexecdir}/ipsec \
  FINALRUNDIR=%{_rundir}/pluto \
  MANTREE=%{buildroot}%{_mandir} \
  INC_RCDEFAULT=%{_initrddir} \
%if %{?rhel} <= 6
  INITSYSTEM=sysvinit \
%else
  INITSYSTEM=systemd \
%endif
  USE_NM=%{USE_NM} \
  USE_XAUTHPAM=true \
  USE_FIPSCHECK="%{USE_FIPSCHECK}" \
  USE_LIBCAP_NG="%{USE_LIBCAP_NG}" \
  USE_LABELED_IPSEC="%{USE_LABELED_IPSEC}" \
  USE_LINUX_AUDIT="%{USE_LINUX_AUDIT}" \
%if %{crl_fetching}
  USE_LDAP=true \
  USE_LIBCURL=true \
%else
  USE_LDAP=false \
  USE_LIBCURL=false \
%endif
  USE_DNSSEC="%{USE_DNSSEC}" \
  USE_SECCOMP="%{USE_SECCOMP}" \
  NSS_HAS_IPSEC_PROFILE="%{NSS_HAS_IPSEC_PROFILE}" \
  USE_DH22=true \
  install
FS=$(pwd)
rm -rf %{buildroot}/usr/share/doc/libreswan
sed -i "s:^#include /etc/ipsec.d/\*.conf$:include /etc/ipsec.d/*.conf:" %{buildroot}%{_sysconfdir}/ipsec.conf

install -d -m 0755 %{buildroot}%{_localstatedir}/run/pluto
# used when setting --perpeerlog without --perpeerlogbase
install -d -m 0700 %{buildroot}%{_localstatedir}/log/pluto/peer
install -d %{buildroot}%{_sbindir}
%if %{?rhel} <= 6
# replace with rhel6 specific version
install -m 0755 initsystems/sysvinit/init.rhel %{buildroot}%{_initrddir}/ipsec
rm -fr %{buildroot}/etc/rc.d/rc*
%endif

%if %{USE_FIPSCHECK}
%if %{?rhel} == 7
mkdir -p %{buildroot}%{_libdir}/fipscheck
%endif
install -d %{buildroot}%{_sysconfdir}/prelink.conf.d/
install -m644 packaging/fedora/libreswan-prelink.conf %{buildroot}%{_sysconfdir}/prelink.conf.d/libreswan-fips.conf
%endif

echo "include /etc/ipsec.d/*.secrets" > %{buildroot}%{_sysconfdir}/ipsec.secrets

%if %{cavstests}
%check
# There is an elaborate upstream testing infrastructure which we do not run here
# We only run the CAVS tests here
cp %{SOURCE1} %{SOURCE2} %{SOURCE3} .
bunzip2 *.fax.bz2

# work around for rhel6 builders on xen
export NSS_DISABLE_HW_GCM=1

: "starting CAVS test for IKEv2"
%{buildroot}%{_libexecdir}/ipsec/cavp -v2 ikev2.fax | diff -u ikev2.fax - > /dev/null
: "starting CAVS test for IKEv1 RSASIG"
%{buildroot}%{_libexecdir}/ipsec/cavp -v1dsa ikev1_dsa.fax | diff -u ikev1_dsa.fax - > /dev/null
: "starting CAVS test for IKEv1 PSK"
%{buildroot}%{_libexecdir}/ipsec/cavp -v1psk ikev1_psk.fax | diff -u ikev1_psk.fax - > /dev/null
: "CAVS tests passed"
%endif

%if %{?rhel} <= 6
%post
/sbin/chkconfig --add ipsec || :
%if %{USE_FIPSCHECK}
prelink -u %{_libexecdir}/ipsec/* 2>/dev/null || :
%endif

%preun
if [ $1 -eq 0 ]; then
    /sbin/service ipsec stop > /dev/null 2>&1 || :
    /sbin/chkconfig --del ipsec
fi

%postun
if [ $1 -ge 1 ] ; then
     /sbin/service ipsec condrestart 2>&1 >/dev/null || :
fi
%else
%preun
%systemd_preun ipsec.service

%postun
%systemd_postun_with_restart ipsec.service

%post
%systemd_post ipsec.service
%endif

%files
%doc CHANGES COPYING CREDITS README* LICENSE
%doc docs/*.* docs/examples packaging/rhel/libreswan-sysctl.conf

%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.conf
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/ipsec.secrets
%attr(0700,root,root) %dir %{_sysconfdir}/ipsec.d
%attr(0700,root,root) %dir %{_sysconfdir}/ipsec.d/policies
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.d/policies/*
%attr(0700,root,root) %dir %{_localstatedir}/log/pluto/peer
%attr(0755,root,root) %dir %{_localstatedir}/run/pluto
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/pam.d/pluto
%{_sbindir}/ipsec
%attr(0755,root,root) %dir %{_libexecdir}/ipsec
%{_libexecdir}/ipsec/*
%attr(0644,root,root) %{_mandir}/*/*.gz
%if %{?rhel} <= 6
%{_initrddir}/ipsec
%else
%attr(0644,root,root) %{_unitdir}/ipsec.service
%endif

%if %{USE_FIPSCHECK}
%if %{?rhel} <= 6
%{_sbindir}/.ipsec.hmac
%{_libexecdir}/ipsec/.*.hmac
%else
%{_libdir}/fipscheck/*.hmac
%endif

# We own the directory so we don't have to require prelink
%attr(0755,root,root) %dir %{_sysconfdir}/prelink.conf.d/
%{_sysconfdir}/prelink.conf.d/libreswan-fips.conf
%endif

%changelog
* Wed Aug 28 2019 Paul Wouters <pwouters@redhat.com> - 3.25-8.1
- Resolves: rhbz#1746052 libreswan: XFRM policy for OE/32 peer is deleted when shunts for previous half-open state expire [rhel-7.7.z]

* Tue May 07 2019 Paul Wouters <pwouters@redhat.com> - 3.25-8
- Resolves: rhbz#1686991 IKEv1 traffic interruption when responder deletes SAs 60 seconds before EVENT_SA_REPLACE

* Wed Feb 27 2019 Paul Wouters <pwouters@redhat.com> - 3.25-7
- Resolves: rhbz#1673105 Opportunistic IPsec instances of /32 groups or auto=start that receive delete won't restart

* Mon Feb 04 2019 Paul Wouters <pwouters@redhat.com> - 3.25-6
- Resolves: rhbz#1630355 Libreswan crash upon receiving ISAKMP_NEXT_D with appended ISAKMP_NEXT_N [updated]
- Resolves: rhbz#1679735 libreswan using NSS IPsec profiles regresses when critical flags are set causing validation failure

* Thu Dec 20 2018 Paul Wouters <pwouters@redhat.com> - 3.25-5
- Resolves: rhbz#1639404 Unable to verify certificate with non-empty Extended Key Usage which does not include serverAuth or clientAuth
- Resolves: rhbz#1630355 Libreswan crash upon receiving ISAKMP_NEXT_D with appended ISAKMP_NEXT_N
- Resolves: rhbz#1629902 libreswan assertion failed when OAKLEY_KEY_LENGTH is zero for IKE using AES_CBC
- Resolves: rhbz#1623279 [abrt] [faf] libreswan: strncpy(): /usr/libexec/ipsec/pluto killed by 11
- Resolves: rhbz#1625303 config: recursive include check doesn't work
- Resolves: rhbz#1664521 libreswan 3.25 in FIPS mode is incorrectly rejecting X.509 public keys that are >= 3072 bits

* Mon Jul 02 2018 Paul Wouters <pwouters@redhat.com> - 3.25-2
- Resolves: rhbz#1597322 Relax deleting IKE SA's and IPsec SA's to avoid interop issues with third party VPN vendors

* Wed Jun 27 2018 Paul Wouters <pwouters@redhat.com> - 3.25-1
- Resolves: rhbz#1591817 rebase libreswan to 3.25
- Resolves: rhbz#1536404 CERT_PKCS7_WRAPPED_X509 error
- Resolves: rhbz#1544143 ipsec newhostkey fails in FIPS mode when RSA key is generated
- Resolves: rhbz#1574011 libreswan is missing a Requires: unbound-libs >= 1.6.6

* Fri Apr 27 2018 Paul Wouters <pwouters@redhat.com> - 3.23-4
- Resolves: rhbz#1544143 ipsec newhostkey fails in FIPS mode when RSA key is generated
- Resolves: rhbz#1553406 IKEv2 liveness false positive on IKEv2 idle connections causes tunnel to be restarted
- Resolves: rhbz#1572425 shared IKE SA leads to rekey interop issues

* Wed Feb 07 2018 Paul Wouters <pwouters@redhat.com> - 3.23-3
- Resolves: rhbz#1471553 libreswan postquantum preshared key (PPK) support [IANA update]

* Tue Feb 06 2018 Paul Wouters <pwouters@redhat.com> - 3.23-2
- Resolves: rhbz#1457904 rebase libreswan to 3.23 [updated]
- Resolves: rhbz#1375750 SECCOMP support for libreswan [updated]

* Thu Jan 25 2018 Paul Wouters <pwouters@redhat.com> - 3.23-1
- Resolves: rhbz#1457904 rebase libreswan to 3.23 [updated]

* Thu Jan 11 2018 Paul Wouters <pwouters@redhat.com> - 3.23-0.1.rc4
- Resolves: rhbz#1471763 RFE: libreswan MOBIKE support (RFC-4555) [client support]
- Resolves: rhbz#1457904 rebase libreswan to 3.23 [updated]
- Resolves: rhbz#1471553 libreswan postquantum preshared key (PPK) support
- Resolves: rhbz#1492501 Reboot or 'systemctl stop ipsec' brings down _ethernet_ interfaces on _both_ ends of ipv4 ipsec tunnel
- Resolves: rhbz#1324421 libreswan works not well when setting leftid field to be email address
- Resolves: rhbz#1136076 After IKE rekeying Pluto sends DPD even if there is active SA

* Tue Dec 12 2017 Paul Wouters <pwouters@redhat.com> - 3.22-5
- Resolves: rhbz#1471763 RFE: libreswan MOBIKE support (RFC-4555) [updated]
- Resolves: rhbz#1471553 libreswan postquantum preshared key (PPK) support
- Resolves: rhbz#1375776 [IKEv2 Conformance] Test IKEv2.EN.R.1.2.2.1: Receipt of retransmitted CREATE_CHILD_SA reques failed
- Resolves: rhbz#1375750 SECCOMP support for libreswan [updated for libunbound syscalls]
- Resolves: rhbz#1300763 Implement draft-ietf-ipsecme-split-dns for libreswan

* Thu Nov 30 2017 Paul Wouters <pwouters@redhat.com> - 3.22-4
- Resolves: rhbz#1463062 NIC-card hardware offload support backport

* Thu Nov 16 2017 Paul Wouters <pwouters@redhat.com> - 3.22-3
- Resolves: rhbz#1475434 Add support for AES-GMAC for ESP (RFC-4543) to libreswan
- Resolves: rhbz#1300759 Implement RFC-7427 Digital Signature authentication

* Tue Oct 31 2017 Paul Wouters <pwouters@redhat.com> - 3.22-2
- Resolves: rhbz#1471763 RFE: libreswan MOBIKE support (RFC-4555)
- Resolves: rhbz#1372050 RFE: Support IKE and ESP over TCP: RFC 8229

* Mon Oct 23 2017 Paul Wouters <pwouters@redhat.com> - 3.22-1
- Resolves: rhbz#1457904 rebase libreswan to 3.22 [updated]

* Mon Oct 16 2017 Paul Wouters <pwouters@redhat.com> - 3.21-2
- Resolves: rhbz#1499845 libreswan does not establish IKE with xauth enabled but modecfg disabled
- Resolves: rhbz#1497158 xauth password length limited to 64 bytes while XAUTH_MAX_PASS_LENGTH (128)

* Wed Sep 20 2017 Paul Wouters <pwouters@redhat.com> - 3.21-1
- Resolves: rhbz#1457904 rebase libreswan to 3.22

* Mon Jun 12 2017 Paul Wouters <pwouters@redhat.com> - 3.20-3
- Resolves: rhbz#1372279 ipsec auto --down CONNECTION returns error for tunnels [updated]
- Resolves: rhbz#1458227 CAVS test driver does not work in FIPS mode
- Resolves: rhbz#1452672 (new-ksk-libreswan-el7) DNSSEC trust anchor cannot be updated without recompilation

* Thu Apr 13 2017 Paul Wouters <pwouters@redhat.com> - 3.20-2
- Resolves: rhbz#1372279 ipsec auto --down CONNECTION returns error for tunnels
- Resolves: rhbz#1444115 FIPS: libreswan must generate RSA keys with a minimal exponent of F4, nor E=3
- Resolves: rhbz#1341353 Allow Preshared Key authentication in FIPS mode for libreswan

* Tue Mar 14 2017 Paul Wouters <pwouters@redhat.com> - 3.20-1
- Resolves: rhbz#1399883 rebase libreswan to 3.20 (full release)

* Mon Feb 20 2017 Paul Wouters <pwouters@redhat.com> - 3.20-0.1.dr3
- Resolves: rhbz#1399883 rebase libreswan to 3.20

* Wed Sep 07 2016 Paul Wouters <pwouters@redhat.com> - 3.15-8
- Resolves: rhbz#1361721 libreswan pluto segfault [UPDATED]
- Resolves: rhbz#1276524 [USGv6] IKEv2.EN.R.1.1.3.2 case failed due to response to bad INFORMATIONAL request [UPDATED]
- Resolves: rhbz#1309764 ipsec barf [additional man page update and --no-pager]

* Mon Aug 08 2016 Paul Wouters <pwouters@redhat.com> - 3.15-7
- Resolves: rhbz#1311360  When IKE rekeys, if on a different tunnel, all subsequent attempts to rekey fail
- Resolves: rhbz#1361721 libreswan pluto segfault

* Tue Jul 05 2016 Paul Wouters <pwouters@redhat.com> - 3.15-6
- Resolves: rhbz#1283468 keyingtries=0 is broken
- Resolves: rhbz#1297816 When using SHA2 as PRF algorithm, nonce payload is below the RFC minimum size
- Resolves: rhbz#1344567 CVE-2016-5361 libreswan: IKEv1 protocol is vulnerable to DoS amplification attack
- Resolves: rhbz#1313747 ipsec pluto returns zero even if it fails
- Resolves: rhbz#1302778 fips does not check hash of some files (like _import_crl)
- Resolves: rhbz#1278063 Unable to authenticate with PAM for IKEv1 XAUTH
- Resolves: rhbz#1257079 Libreswan doesn't call NetworkManager helper in case of a connection error
- Resolves: rhbz#1272112 ipsec whack man page discrepancies
- Resolves: rhbz#1280449 PAM xauth method does not work with pam_sss
- Resolves: rhbz#1290907 ipsec initnss/checknss custom directory not recognized
- Resolves: rhbz#1309764 ipsec barf does not show pluto log correctly in the output
- Resolves: rhbz#1347735 libreswan needs to check additional CRLs after LDAP CRL distributionpoint fails
- Resolves: rhbz#1219049 Pluto does not handle delete message from responder site in ikev1
- Resolves: rhbz#1276524 [USGv6] IKEv2.EN.R.1.1.3.2 case failed due to response to bad INFORMATIONAL request
- Resolves: rhbz#1315412 ipsec.conf manpage does not contain any mention about crl-strict option
- Resolves: rhbz#1229766 Pluto crashes after stop when I use floating ip address

* Wed Oct 21 2015 Paul Wouters <pwouters@redhat.com> - 3.15-5
- Resolves: rhbz#1271811 libreswan FIPS test mistakenly looks for non-existent file hashes

* Wed Sep 30 2015 Paul Wouters <pwouters@redhat.com> - 3.15-4
- Resolves: rhbz#1267370 libreswan should support strictcrlpolicy alias
- Resolves: rhbz#1229766 Pluto crashes after stop when I use floating ip address
- Resolves: rhbz#1166146 Pluto crashes on INITIATOR site during 'service ipsec stop'
- Resolves: rhbz#1259209 CVE-2015-3240
- Resolves: rhbz#1199374 libreswan does not enforce all FIPS or IPsec Suite B restrictions
- Resolves: rhbz#1207689 libreswan ignores module blacklist rules
- Merge rhel6 and rhel7 spec into one
- Be lenient for racoon padding behaviour
- Fix seedev option to /dev/random
- Some IKEv1 PAM methods always gave 'Permission denied'
- Parser workarounds for differences in gcc/flex/bison on rhel6/rhel7
- Parser fix to allow specifying time without unit (openswan compat)
- Fix Labeled IPsec on rekeyed IPsec SA's
- Workaround for wrong padding by racoon2
- Disable NSS HW GCM to workaround rhel6 xen builers bug

* Fri May 29 2015 Paul Wouters <pwouters@redhat.com> - 3.12-12
- Resolves: rhbz#1212121 Support CAVS [updated bogus fips mode fix]

* Fri May 29 2015 Paul Wouters <pwouters@redhat.com> - 3.12-11
- Resolves: rhbz#1226408 CVE-2015-3204 libreswan: crafted IKE packet causes daemon restart

* Tue May 05 2015 Paul Wouters <pwouters@redhat.com> - 3.12-10
- Resolves: rhbz#1212121 Support CAVS testing of the PRF/PRF+ functions
- Resolves: rhbz#1127313 Libreswan with IPv6 [updated patch by Jaroslav Aster]
- Resolves: rhbz#1207689 libreswan ignores module blacklist [updated modprobe handling]
- Resolves: rhbz#1218358 pluto crashes in fips mode without dracut-fips package

* Sat Feb 21 2015 Paul Wouters <pwouters@redhat.com> - 3.12-6
- Resolves: rhbz#1056559 loopback support deprecated
- Resolves: rhbz#1182224 Add new option for BSI random requirement
- Resolves: rhbz#1170018 [increase] SELinux context string size limit
- Resolves: rhbz#1127313 Libreswan with IPv6 in RHEL7 fails after reboot
- Resolves: rhbz#1207689 libreswan ignores module blacklist rules
- Resolves: rhbz#1203794 pluto crashes in fips mode

* Tue Jan 20 2015 Paul Wouters <pwouters@redhat.com> - 3.12-5
- Resolves: rhbz#826264 aes-gcm implementation support (for IKEv2)
- Resolves: rhbz#1074018 Audit key agreement (integ gcm fixup)

* Tue Dec 30 2014 Paul Wouters <pwouters@redhat.com> - 3.12-4
- Resolves: rhbz#1134297 aes-ctr cipher is not supported
- Resolves: rhbz#1131503 non-zero rSPI on INVALID_KE (and proper INVALID_KE handling)

* Thu Dec 04 2014 Paul Wouters <pwouters@redhat.com> - 3.12-2
- Resolves: rhbz#1105171 (Update man page entry)
- Resolves: rhbz#1144120 (Update for ESP CAMELLIA with IKEv2)
- Resolves: rhbz#1074018 Audit key agreement

* Fri Nov 07 2014 Paul Wouters <pwouters@redhat.com> - 3.12-1
- Resolves: rhbz#1136124 rebase to libreswan 3.12
- Resolves: rhbz#1052811 [TAHI] (also clear reserved flags for isakmp_sa header)
- Resolves: rhbz#1157379 [TAHI][IKEv2] IKEv2.EN.R.1.3.3.1: Non RESERVED fields in INFORMATIONAL request

* Mon Oct 27 2014 Paul Wouters <pwouters@redhat.com> - 3.11-2
- Resolves: rhbz#1136124 rebase to libreswan 3.11 (coverity fixup, dpdaction=clear fix)

* Wed Oct 22 2014 Paul Wouters <pwouters@redhat.com> - 3.11-1
- Resolves: rhbz#1136124 rebase to libreswan 3.11
- Resolves: rhbz#1099905 ikev2 delete payloads are not delivered to peer
- Resolves: rhbz#1147693 NetworkManger-libreswan can not connect to Red Hat IPSec Xauth VPN
- Resolves: rhbz#1055865 [TAHI][IKEv2] libreswan do not ignore the content of version bit
- Resolves: rhbz#1146106 Pluto crashes after start when some ah algorithms are used
- Resolves: rhbz#1108256 addconn compatibility with openswan
- Resolves: rhbz#1152625 [TAHI][IKEv2] IKEv2.EN.I.1.1.6.2 Part D: Integrity Algorithm AUTH_AES_XCBC_96 fail
- Resolves: rhbz#1119704 [TAHI][IKEv2]IKEv2Interop.1.13a test fail
- Resolves: rhbz#1100261 libreswan does not send response when when it receives Delete Payload for a CHILD_SA
- Resolves: rhbz#1100239 ikev2 IKE SA responder does not send delete request to IKE SA initiator
- Resolves: rhbz#1052811 [TAHI][IKEv2]IKEv2.EN.I.1.1.11.1: Non zero RESERVED fields in IKE_SA_INIT response
- Resolves: rhbz#1126868 ikev2 sequence numbers are implemented incorrectly
- Resolves: rhbz#1145245 Libreswan appears to start with systemd before all the NICs are up and running.
- Resolves: rhbz#1145231 libreswan 3.10 upgrade breaks old ipsec.secrets configs
- Resolves: rhbz#1144123 Add ESP support for AES_XCBC hash for USGv6 and IPsec-v3 compliance
- Resolves: rhbz#1144120 Add ESP support for CAMELLIA for USGv6 and IPsec-v3 compliance
- Resolves: rhbz#1099877 Missing man-pages ipsec_whack, ipsec_manual
- Resolves: rhbz#1100255 libreswan Ikev2 implementation does not send an INFORMATIONAL response when it receives an INFORMATIONAL request with a Delete Payload for an IKE_SA

* Tue Sep 09 2014 Paul Wouters <pwouters@redhat.com> - 3.10-3
- Resolves: rhbz#1136124 rebase to 3.10 (auto=route bug on startup)

* Mon Sep 08 2014 Paul Wouters <pwouters@redhat.com> - 3.10-2
- Resolves: rhbz#1136124 rebase to libreswan 3.10

* Mon Jul 14 2014 Paul Wouters <pwouters@redhat.com> - 3.8-6
- Resolves: rhbz#1092047 pluto cannot write to directories not owned by root

* Thu Apr 10 2014 Paul Wouters <pwouters@redhat.com> - 3.8-5
- Resolves: rhbz#1052834 create_child_sa message ID handling


* Tue Mar 18 2014 Paul Wouters <pwouters@redhat.com> - 3.8-4
- Resolves: rhbz#1052834 create_child_sa response

* Wed Mar 05 2014 Paul Wouters <pwouters@redhat.com> - 3.8-3
- Resolves: rhbz#1069024  erroneous debug line with mixture [...]
- Resolves: rhbz#1030939 update nss/x509 documents, don't load acerts
- Resolves: rhbz#1058813 newhostkey returns zero value when it fails

* Fri Jan 24 2014 Daniel Mach <dmach@redhat.com> - 3.8-2
- Mass rebuild 2014-01-24

* Thu Jan 16 2014 Paul Wouters <pwouters@redhat.com> - 3.8-1
- Resolves: rhbz#CVE-2013-6467 
- Resolves: rhbz#1043642 rebase to version 3.8
- Resolves: rhbz#1029912 ipsec force-reload doesn't work
- Resolves: rhbz#826261 Implement SHA384/512 support for Openswan
- Resolves: rhbz#1039655 ipsec newhostkey generates false configuration

* Fri Dec 27 2013 Daniel Mach <dmach@redhat.com> - 3.6-3
- Mass rebuild 2013-12-27

* Fri Nov 08 2013 Paul Wouters <pwouters@redhat.com> - 3.6-2
- Fix race condition in post for creating nss db

* Thu Oct 31 2013 Paul Wouters <pwouters@redhat.com> - 3.6-1
- Updated to version 3.6 (IKEv2, MODECFG, Cisco interop fixes)
- Generate empty NSS db if none exists
- FIPS update using /etc/system-fips
- Provide: openswan-doc

* Fri Aug 09 2013 Paul Wouters <pwouters@redhat.com> - 3.5-2
- rebuilt and bumped EVR to avoid confusion of import->delete->import
- require iproute

* Mon Jul 15 2013 Paul Wouters <pwouters@redhat.com> - 3.5-1
- Initial package for RHEL7
- Added interop patch for (some?) Cisco VPN clients sending 16 zero
  bytes of extraneous IKE data
- Removed fipscheck_version
