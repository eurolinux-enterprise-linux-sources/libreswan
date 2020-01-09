%global USE_FIPSCHECK true
%global USE_LIBCAP_NG true
%global USE_LABELED_IPSEC true
%global USE_CRL_FETCHING true
%global USE_DNSSEC true
%global USE_NM true
%global USE_LINUX_AUDIT true

%global _hardened_build 1
%global buildefence 0
%global development 0
%global cavstests 1

%if 0%{?fedora}
%global rhel 7
%endif

#global prever rc1

Name: libreswan
Summary: IPsec implementation with IKEv1 and IKEv2 keying protocols
Version: 3.15
Release: %{?prever:0.}7.3%{?prever:.%{prever}}%{?dist}
License: GPLv2
Group: System Environment/Daemons
Url: https://libreswan.org/
Source: https://download.libreswan.org/%{?prever:development/}%{name}-%{version}%{?prever}.tar.gz
Source1: ikev1_dsa.fax.bz2
Source2: ikev1_psk.fax.bz2
Source3: ikev2.fax.bz2

Patch1: libreswan-3.15-racoon-padding.patch
Patch2: libreswan-3.15-seeddev.patch
Patch3: libreswan-3.15-ikev1-pam.patch
Patch4: libreswan-3.15-gcc-osw-interop-conf.patch
Patch5: libreswan-3.15-newest-labeled.patch
Patch6: libreswan-3.15-s90-gcc.patch
Patch7: libreswan-3.15-NLMSG_OK.patch
Patch8: libreswan-3.15-trafficstatus.patch
Patch9: libreswan-3.15-cisco-delete.patch
Patch10: libreswan-3.15-migration.patch
Patch11: libreswan-3.15-1166146.patch
Patch12: libreswan-3.15-609343.patch
Patch13: libreswan-3.15-1271778-whack-man.patch
# rhbz#1272317
Patch14: libreswan-3.15-1271811-fipsfiles.patch
Patch15: libreswan-3.15-1289498-keyingtries.patch
Patch16: libreswan-3.15-1144462-status.patch
Patch17: libreswan-3.16-1311360-sharedike.patch
# rhbz#1360134
Patch18: libreswan-3.15-1347735-multicrl.patch
Patch19: libreswan-3.15-1313709-man-rcode.patch
Patch20: libreswan-3.15-1315415-man-crl-strict.patch
# rhbz#1375741
Patch21: libreswan-3.15-1361721-delete.patch
Patch22: libreswan-3.18-1375741-avoid_dup_shunt.patch
# rhbz#1335896
Patch23: libreswan-3.15-1290907-configdir.patch
Patch24: libreswan-3.18-1313843-initwarn.patch
Patch25: libreswan-3.18-1369990-delete-init.patch
Patch26: libreswan-3.15-1403201-memleak-backports.patch

Requires: iproute >= 2.6.8 nss-tools nss-softokn

BuildRequires: gmp-devel bison flex redhat-rpm-config pkgconfig
BuildRequires: nss-devel >= 3.16.1 nspr-devel
BuildRequires: pam-devel
BuildRequires: xmlto

%if %{?rhel} <= 6
BuildRequires: libevent2-devel net-tools

Requires(post): coreutils bash
Requires(preun): initscripts chkconfig
Requires(post): /sbin/chkconfig
Requires(preun): /sbin/chkconfig
Requires(preun): /sbin/service
%else
BuildRequires: libevent-devel hostname

BuildRequires: systemd
Requires(post): coreutils bash systemd
Requires(preun): systemd
Requires(postun): systemd
%endif

%if %{USE_DNSSEC}
BuildRequires: unbound-devel
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

%if %{USE_CRL_FETCHING}
BuildRequires: openldap-devel curl-devel
%endif

%if %{buildefence}
BuildRequires: ElectricFence
%endif

Conflicts: openswan < %{version}-%{release}
Obsoletes: openswan < %{version}-%{release}
Provides: openswan = %{version}-%{release}
Provides: openswan-doc = %{version}-%{release}

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
%patch13 -p1
%patch14 -p1
%patch15 -p1
%patch16 -p1
%patch17 -p1
%patch18 -p1
%patch19 -p1
%patch20 -p1
%patch21 -p1
%patch22 -p1
%patch23 -p1
%patch24 -p1
%patch25 -p1
%patch26 -p1

%build
%if %{buildefence}
 %define efence "-lefence"
%endif

make %{?_smp_mflags} \
%if %{development}
   USERCOMPILE="-g -DGCC_LINT %(echo %{optflags} | sed -e s/-O[0-9]*/ /) %{?efence} -fPIE -pie " \
%else
  USERCOMPILE="-g -DGCC_LINT %{optflags} %{?efence} -fPIE -pie " \
%endif
  USERLINK="-g -pie -Wl,-z,relro,-z,now %{?efence}" \
%if %{?rhel} <= 6
  INITSYSTEM=sysvinit \
%else
  INITSYSTEM=systemd \
%endif
  USE_NM=%{USE_NM} \
  USE_XAUTHPAM=true \
%if %{USE_FIPSCHECK}
  USE_FIPSCHECK="%{USE_FIPSCHECK}" \
  FIPSPRODUCTCHECK=/etc/system-fips \
%endif
  USE_LIBCAP_NG="%{USE_LIBCAP_NG}" \
  USE_LABELED_IPSEC="%{USE_LABELED_IPSEC}" \
  USE_LINUX_AUDIT="%{USE_LINUX_AUDIT}" \
%if %{USE_CRL_FETCHING}
  USE_LDAP=true \
  USE_LIBCURL=true \
%endif
  USE_DNSSEC="%{USE_DNSSEC}" \
  INC_USRLOCAL=%{_prefix} \
  FINALLIBDIR=%{_libexecdir}/ipsec \
  FINALLIBEXECDIR=%{_libexecdir}/ipsec \
  MANTREE=%{_mandir} \
  INC_RCDEFAULT=%{_initrddir} \
  MODPROBE="modprobe -q -b" \
  WERROR_CFLAGS="" \
  programs
FS=$(pwd)

%if %{USE_FIPSCHECK}
# Add generation of HMAC checksums of the final stripped binaries
%if %{?rhel} <= 6
%define __spec_install_post \
    %{?__debug_package:%{__debug_install_post}} \
    %{__arch_install_post} \
    %{__os_install_post} \
    fipshmac %{buildroot}%{_libexecdir}/ipsec/* \
    fipshmac %{buildroot}%{_sbindir}/ipsec \
%{nil}

%else
%define __spec_install_post \
    %{?__debug_package:%{__debug_install_post}} \
    %{__arch_install_post} \
    %{__os_install_post} \
    mkdir -p %{buildroot}%{_libdir}/fipscheck/ \
    fipshmac -d %{buildroot}%{_libdir}/fipscheck %{buildroot}%{_libexecdir}/ipsec/* \
    fipshmac -d %{buildroot}%{_libdir}/fipscheck %{buildroot}%{_sbindir}/ipsec \
%{nil}
%endif
%endif

%install
rm -rf ${RPM_BUILD_ROOT}
make \
  DESTDIR=%{buildroot} \
  INC_USRLOCAL=%{_prefix} \
  FINALLIBDIR=%{_libexecdir}/ipsec \
  FINALLIBEXECDIR=%{_libexecdir}/ipsec \
  MANTREE=%{buildroot}%{_mandir} \
  INC_RCDEFAULT=%{_initrddir} \
  INSTMANFLAGS="-m 644" \
%if %{?rhel} <= 6
  INITSYSTEM=sysvinit \
%else
  INITSYSTEM=systemd \
%endif
  install
FS=$(pwd)
rm -rf %{buildroot}/usr/share/doc/libreswan
# needed to activate v6neighbor-hole.conf
sed -i "s:^#include /etc/ipsec.d/\*.conf$:include /etc/ipsec.d/*.conf:" %{buildroot}%{_sysconfdir}/ipsec.conf

install -d -m 0700 %{buildroot}%{_localstatedir}/run/pluto
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

# cavs testing
cp -a OBJ.linux.*/programs/pluto/cavp %{buildroot}%{_libexecdir}/ipsec

%if %{cavstests}
%check
# There is an elaborate upstream testing infrastructure which we do not run here
# We only run the CAVS tests here
cp %{SOURCE1} %{SOURCE2} %{SOURCE3} .
bunzip2 *.fax.bz2

# work around for rhel6 builders on xen
export NSS_DISABLE_HW_GCM=1

: "starting CAVS test for IKEv2"
OBJ.linux.*/programs/pluto/cavp -v2 ikev2.fax | diff -u ikev2.fax - > /dev/null
: "starting CAVS test for IKEv1 RSASIG"
OBJ.linux.*/programs/pluto/cavp -v1sig ikev1_dsa.fax | diff -u ikev1_dsa.fax - > /dev/null
: "starting CAVS test for IKEv1 PSK"
OBJ.linux.*/programs/pluto/cavp -v1psk ikev1_psk.fax | diff -u ikev1_psk.fax - > /dev/null
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
     /sbin/service ipsec condrestart >/dev/null 2>&1 || :
fi

%else
%preun
%systemd_preun ipsec.service

%postun
%systemd_postun_with_restart ipsec.service

%post
%systemd_post ipsec.service
%endif

# handling for rhbz#1345959 openswan to libreswan migration
%triggerun -- openswan < %{version}-%{release}
/sbin/chkconfig ipsec >/dev/null 2>&1 && \
    touch %{_localstatedir}/lock/subsys/ipsec.enabled || :
/sbin/service ipsec status >/dev/null 2>&1 && \
    touch %{_localstatedir}/lock/subsys/ipsec.started || :
for conf in $(ls %{_sysconfdir}/ipsec.conf %{_sysconfdir}/ipsec.d/*.conf 2>/dev/null); do
    grep -q 'ike=.*!$' ${conf} && sed -i.rpmorig -e '/ike=/ s/\!$//' ${conf} || :
done

%triggerpostun -- openswan < %{version}-%{release}
/sbin/chkconfig --add ipsec
if [ -f %{_localstatedir}/lock/subsys/ipsec.enabled ]; then
    /sbin/chkconfig ipsec on
    rm -f %{_localstatedir}/lock/subsys/ipsec.enabled
fi
if [ -f %{_localstatedir}/lock/subsys/ipsec.started ]; then
    /sbin/service ipsec restart >/dev/null 2>&1
    rm -f %{_localstatedir}/lock/subsys/ipsec.started
fi

%files
%doc CHANGES COPYING CREDITS README* LICENSE
%doc docs/*.* docs/examples packaging/rhel/libreswan-sysctl.conf

%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.conf
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/ipsec.secrets
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/sysconfig/pluto
%attr(0700,root,root) %dir %{_sysconfdir}/ipsec.d
%attr(0644,root,root) %{_sysconfdir}/ipsec.d/v6neighbor-hole.conf
%attr(0700,root,root) %dir %{_sysconfdir}/ipsec.d/policies
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.d/policies/*
%attr(0700,root,root) %dir %{_localstatedir}/log/pluto/peer
%attr(0700,root,root) %dir %{_localstatedir}/run/pluto
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
* Sun Jan 15 2017 Paul Wouters <pwouters@redhat.com> - 3.15-7.3
- Resolves: rhbz#1403201 pluto uses up available memory and fails with 'unable to popen'
- Resolves: rhbz#1311360 When IKE rekeys [...] (updated for IKEv1 responder side)

* Mon Nov 21 2016 Paul Wouters <pwouters@redhat.com> - 3.15-7.2
- Resolves: rhbz#1313843 Prescript warning: Missing control file /var/run/pluto/pluto.ctl
- Resolves: rhbz#1375741 Pluto (libreswan) intermittent abort [extended patch]
- Resolves: rhbz#1369990 Libreswan connection sometimes does not get re-established after one side restarts

* Thu Nov 03 2016 Paul Wouters <pwouters@redhat.com> - 3.15-7.1
- Resolves: rhbz#1375741 Pluto (libreswan) intermittent abort when ' auto --up --asynchronous' is used
- Resolves: rhbz#1335896 ipsec initnss/checknss custom directory not recognized

* Wed Aug 24 2016 Paul Wouters <pwouters@redhat.com> - 3.15-7
- Resolves: rhbz#1313843 Prescript warning: Missing control file /var/run/pluto/pluto.ctl

* Wed Aug 24 2016 Paul Wouters <pwouters@redhat.com> - 3.15-6
- Resolves: rhbz#1345959 openswan - libreswan migration issues
- Resolves: rhbz#1360134 libreswan needs to check additional CRLs after LDAP CRL distributionpoint fails
- Resolves: rhbz#1313709 ipsec pluto returns zero even if it fails [doc change only]
- Resolves: rhbz#1315415 ipsec.conf manpage does not contain any mention about crl-strict option

* Mon Mar 07 2016 Paul Wouters <pwouters@redhat.com> - 3.15-5.3
- Resolves: rhbz#1311360 When IKE rekeys, if on a different tunnel [...]

* Sat Jan 23 2016 Paul Wouters <pwouters@redhat.com> - 3.15-5.2
- Resolves: rhbz#1289498 keyingtries=0 is broken
- Resolves: rhbz#1166151 Pluto crashes on during 'service ipsec stop'
- Resolves: rhbz#1216946 IPv6 in RHEL6 fails after reboot
- Resolves: rhbz#1144462 ikev2 status shows "no tunnels up" while tunnel is up

* Wed Dec 02 2015 Paul Wouters <pwouters@redhat.com> - 3.15-5.1
- Resolves: rhbz#1284966 add libreswan to RHEL6 (core)
- Resolves: rhbz#1288086 /var/run/pluto should have 755 and should have 700
