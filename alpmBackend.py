#!/usr/bin/python3
# -*- coding: utf-8 -*-
# vim:set shiftwidth=4 tabstop=4 expandtab:
#
# Copyright (C) 2014 ck Lux <lux.r.ck@gmail.com>
#
# Licensed under the GNU General Public License Version 2
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

__author__ = 'ck Lux <lux.r.ck@gmail.com>'

import json
from packagekit.backend import *
from packagekit.enums import *
from pyalpm import *
from pacman import *
import sys
import time
import os

PREFIX = '/usr/local/share/PackageKit/helpers/pacman/'
GROUPS = PREFIX + 'groups.json'
BLACKLIST = PREFIX + 'blacklist.json'
#REPOS = PREFIX + 'repos.json'
CONF = PREFIX + 'pacman.conf'
GROUP_MAP = json.load(open(GROUPS, 'r'))
'''
class RepoCfg:
    def __init__(self, cfg):
        self.cfg = json.load(open(cfg,'r'))
        self.fp = open(cfg, 'w+')
        print(self.cfg)
    def set(self, rid, p, v):
        if not rid in self.cfg.keys():
            self.cfg[rid] = dict()
        self.cfg[rid][p] = v
    def remove(self, rid):
        if not rid in self.cfg.keys():
            return False
        self.cfg.pop(rid)
        return True
    def write(self):
        json.dump(self.cfg, self.fp)

REPOCFG = RepoCfg(REPOS)
'''
def load_blacklist(cache, fl):
    brepos = json.load(open(fl, 'r'))
    for repo in brepos['blocked']:
        cache.set(repo, False)

def update_blacklist(cache, fl):
    json.dump({'blocked':[v[0].name for k,v in cache.repos.items() if not v[1]]},open(fl, 'w+'))

#
# Avaliable filters: installed/~installed; newest/~newest; basename/~basename
#

class PackageKitPacmanBackend(PackageKitBaseBackend, Pacman):
    def __init__(self, cmds, conf):
        Pacman.__init__(self, conf)
        PackageKitBaseBackend.__init__(self, cmds)
        load_blacklist(self.cache(), BLACKLIST)

    def package(self, pkg, info=None):
        if not info:
            info = INFO_AVAILABLE if not pkg.installdate else INFO_INSTALLED
        summary = pkg.desc
        super().package(self.pid(pkg), info, summary)

    #
    # Backend Action Methods
    #

    def pid(self, pkg):
        dn = pkg.db.name
        if dn == 'local':
            dn = 'installed'
        return pkg.name + ';' + pkg.version + ';' + pkg.arch + ';' + dn

    def pkg(self, pid):
        pn, pv, pa, pi = pid.split(';')
        co = self.cache()
        return co.repo(pi).first(pn, [('=',pv)])

    def backend(fn=None, flags={'status':STATUS_QUERY,'allow_cancel':True}):
        def _bcommand(func):
            def _cmd(self, *args, **kwargs):
                self.status(flags['status'])
                self.allow_cancel(flags['allow_cancel'])
                func(self, *args, **kwargs)
            return _cmd
        if not fn:
            return _bcommand
        return _bcommand(fn)

    def search(func):
        def _search(self, filters, keys):
            c = self.cache()
            pkgs = func(c, keys)
            for pkg in PkgFilter(filters).filter(pkgs):
                print(pkg)
                self.package(pkg)
        return _search

    @backend
    @search
    def search_name(c, keys):
        return c.match(keys)

    @backend
    @search
    def search_details(c, keys):
        return c.search(keys)

    @backend
    @search
    def search_group(c, groups):
        pgrp = set()
        for grp in groups:
            try:
                pgrp = pgrp.union(GROUP_MAP[grp])
            except:
                continue
        return c.groups(pgrp)
            
    @backend
    def search_file(self, filters, files):
        '''Works only for installed packages.'''
        if FILTER_NOT_INSTALLED in filters:
            self.error(ERROR_CANNOT_GET_FILELIST,
                       "search-file isn't available with ~installed filter")
            return
        
        pkgs = self.cache().local().all()
        
        for i,f in enumerate(files):
            if f[0] == '/':
                files[i] = f[1:]

        def _match(pkg, keys):
            for key in keys:
                flag = False
                for f in pkg.files:
                    if re.match(key, f[0]):
                        flag = True
                        break
                if not flag:
                    return False
            return True

        for pkg in pkgs:
            if _match(pkg, files):
                self.package(pkg)

    @backend(flags={'status':STATUS_INFO, 'allow_cancel':True})
    def get_update_detail(self, pids):
        c = self.cache()
        oo = c.online()
        lo = c.local()
        updates = []
        obsolutes = ""
        vendor_url = ""
        bugzilla_url = ""
        cve_url = ""
        restart = ""
        update_text = ""
        changelog = ""
        state = ""
        issued = ""
        updated = ""
        for pid in pids:
            lpid = pid.split(';')
            pk = None
            if len(lpid) == 4:
                pn, pv, pa, pi = lpid
                pk = oo.first(pn,[('=',pv)])
            if not pk:
                self.error(ERROR_INTERNAL_ERROR, "could not find %s" % pid)
                return
            updates = []
            updated = 0
            for lk in lo.get(pn):
                updates.append(';'.join([lk.name, lk.version, lk.arch, lk.db.name]))
                if lk.installdate > updated:
                    updated = lk.installdate
            updates = '&'.join(updates)
            issued = time.ctime(pk.builddate)
            if updated:
                updated = time.ctime(pk.installdate)
            else:
                updated = ""
            vendor_url = pk.url
            state = UPDATE_STATE_TESTING if 'testing' in pk.db.name else UPDATE_STATE_STABLE
            self.update_detail(self.pid(pk), updates, obsolutes, vendor_url, bugzilla_url, cve_url, restart, update_text, changelog, state, issued, updated)

    def deps(func):
        def _pkg(self, filters, pids, recursive):
            c = self.cache()
            for pid in pids:
                try:
                    pn, pv, pa, pi = pid.split(';')
                    pk = c.first(pn, [('=', pv)])
                    if not pk:
                        raise NameError
                except:
                    self.error(ERROR_INTERNAL_ERROR, "could not find %s" % pid)
                    return
                pd = func(self, pk, recursive)
                for p in pd:
                    self.package(p)
        return _pkg

    @backend(flags={'status':STATUS_INFO, 'allow_cancel':True})
    @deps
    def depends_on(self, pkg, recursive):
        return self.calc_dependson(pkg, recursive)

    @backend
    def get_packages(self, filters):
        pkgs = PkgFilter(filters).filter(self.cache().all())
        for pkg in pkgs:
            self.package(pkg)

    @backend(flags={'status':STATUS_INFO, 'allow_cancel':True})
    @deps
    def required_by(self, pkg, recursive):
        return self.calc_requiredby(pkg, recursive)

    # Don't know how to get it right...
    @backend
    def what_provides(self, filters, provides_type, values):
        c = self.cache()
        for pkg in c.provide(values):
            self.package(pkg)

    @backend(flags={'status':STATUS_REFRESH_CACHE, 'allow_cancel':False})
    def refresh_cache(self, force):
        self.cache().refresh(force)

    # Don't support transaction_flags...
    def trans(func):
        def _trans(self, flags, pids, *args, **kwargs):
            c = self.cache()
            pkgs = []
            try:
                for pid in pids:
                    pn, pv, pa, pi = pid.split(';')
                    pk = c.repo(pi).first(pn,[('=',pv)])
                if not pk:
                    raise Exception
                pkgs.append(pk)
            except Exception as e:
                self.error(ERROR_PACKAGE_NOT_FOUND, 'Error, could not find %s' % pid)
                return
            c0 = TRANSACTION_FLAG_ONLY_TRUSTED in flags and False
            c1 = TRANSACTION_FLAG_SIMULATE in flags
            func(self, c0, c1, pkgs, *args, **kwargs)
        return _trans

    @backend(flags={'status':STATUS_RUNNING, 'allow_cancel':False})
    @trans
    def install_packages(self, only_trusted, simulate, pkgs):
        self.status(STATUS_INSTALL)
        lo = self.cache().local()
        for pkg in pkgs:
            if lo.first(pkg.name):
                self.error(ERROR_PACKAGE_ALREADY_INSTALLED, "package '%s' is already installed" % self.pid(pkg))
                pkgs.remove(pkg)
                continue
        if simulate:
            for pkg in pkgs:
                deps = [pkg] + self.calc_dependson(pkg, True)
                for p in deps:
                    if p.db.name != 'local':
                        self.package(p, INFO_INSTALLING)
            return
        self.install(pkgs)

#    def install_signature(self, sigtype, key_id, package_id):
#    def install_files(self, transaction_flags, inst_files):

    @backend
    def resolve(self, filters, values):
        co = self.cache()
        pkgs = []
        for value in values:
            pkgs += list(co.get(value))
        for pkg in PkgFilter(filters).filter(pkgs):
            self.package(pkg)

    @backend(flags={'status':STATUS_RUNNING, 'allow_cancel':False})
    @trans
    def remove_packages(self, only_trusted, simulate, pkgs, allowdeps, autoremove):
        def unneeded(pkgs, blacklist):
            for pkg in pkgs:
                rd = set(pkg.compute_requiredby())
                rd.difference_update(blacklist)
                if not len(rd) and pkg.reason == PKG_REASON_DEPEND:
                    yield pkg
        self.status(STATUS_REMOVE)
        lo = self.cache().local()
        for pkg in pkgs:
            if pkg.db.name != 'local':
                self.error(ERROR_PACKAGE_NOT_INSTALLED, "package '%s' is not installed" % self.pid(pkg))
                pkgs.remove(pkg)
                continue
        if simulate:
            rdeps = set()
            rdeps = rdeps.union(set([pkg] + self.calc_requiredby(pkg, True)))
            if allowdeps:
                ddeps = []
                blacklist = set([p.name for p in rdeps])
                for dep in rdeps:
                    ddeps += list(unneeded(self.calc_dependson(dep, False), blacklist))
                rdeps = rdeps.union(ddeps)
            for p in rdeps:
                if p.db.name == 'local':
                    self.package(p, INFO_REMOVING)
            return
        self.remove(pkgs, {'recurse':allowdeps})

    @backend(flags={'status':STATUS_RUNNING, 'allow_cancel':False})
    @trans
    def update_packages(self, only_trusted, simulate, pkgs):
        self.status(STATUS_UPDATE)
        co = self.cache()
        if simulate:
            for pkg in pkgs:
                if vercmp(co.newest(pkg).version, pkg.version) > 0:
                    self.package(pkg, INFO_UPDATING)
            return
        self.update(pkgs)

    @backend(flags={'status':STATUS_INFO, 'allow_cancel':True})
    def get_details(self, pids):
        def pk_group(pkg):
            for k,v in GROUP_MAP.items():
                if set(pkg.groups).issubset(set(v)):
                    return k
            return GROUP_UNKNOWN
        co = self.cache()
        for pid in pids:
            try:
                pk = self.pkg(pid)
                if pk:
                    self.details(pid, ' '.join(pk.licenses), pk_group(pk), pk.desc, pk.url, "", pk.isize)
            except:
                self.error(ERROR_INTERNAL_ERROR, "could not find '%s'" % pid)

    @backend(flags={'status':STATUS_INFO, 'allow_cancel':True})
    def get_files(self, pids):
        lo = self.cache().local()
        for pid in pids:
            try:
                pn, pv, pa, pi = pid.split(';')
                pk = lo.first(pn,[('=', pv)])
                pfl = []
                for fl in pk.files:
                    pfl.append(fl[0])
                self.files(pid, ';'.join(pfl))
                if not pk:
                    raise Exception
            except:
                self.error(ERROR_INTERNAL_ERROR, "could not find '%s'" % pid)
                return

    @backend(flags={'status':STATUS_INFO, 'allow_cancel':True})
    def get_updates(self, filters):
        ipkgs = self.cache().local().all()
        oldbs = self.cache().dbs()[1:]
        for pkg in ipkgs:
            nvp = pyalpm.sync_newversion(pkg, oldbs)
            if nvp:
                self.package(nvp, INFO_NORMAL)

#    def get_distro_upgrades(self):

    @backend(flags={'status':STATUS_INFO, 'allow_cancel':True})
    def repo_enable(self, repoid, enable):
        if repoid == 'core':
            self.error(ERROR_CANNOT_DISABLE_REPOSITORY, "'core' repo can't be disabled")
            return
        self.cache().set(repoid, enable)
        update_blacklist(self.cache(), BLACKLIST)

#    def repo_set_data(self, repoid, parameter, value):
#        co = self.cache()
#        for k in [k for k,v in co.repos.items() if not co.repos[k][1]]:
#            REPOCFG.remove(k)
#        REPOCFG.set(repoid, parameter, value)
#        REPOCFG.write()

    @backend(flags={'status':STATUS_INFO, 'allow_cancel':True})
    def get_repo_list(self, filters):
        co = self.cache()
        keys = list(co.repos.keys())
        keys.sort()
        for v in [co.repos[key] for key in keys]:
            self.repo_detail(v[0].name, v[0].name, v[1])

#    def repo_signature_install(self, package_id):

    @backend(flags={'status':STATUS_RUNNING, 'allow_cancel':False})
    def download_packages(self, directory, pids):
        self.status(STATUS_DOWNLOAD)
        co = self.cache()
        pkgs = []
        try:
            for pid in pids:
                pn, pv, pa, pi = pid.split(';')
                pk = co.repo(pi).first(pn,[('=',pv)])
                if not pk:
                    raise Exception
                pkgs.append(pk)
        except Exception as e:
            self.error(ERROR_PACKAGE_NOT_FOUND, 'Error, cound not find %s' % pid)
            return
        if not directory:
            directory = os.getcwd()
        if not os.access(directory, os.W_OK):
            self.error(ERROR_INTERNAL_ERROR, "directory '%s' isn't writable'" % directory)
            return
        flags = {'directory': directory}
        self.download(pkgs, flags)
        for pkg in pkgs:
            pname = pkg.filename
            self.files(self.pid(pkg), os.path.abspath(directory) + '/' + pname)

#    def set_locale(self, code):
#    def get_categories(self):
#    def repair_system(self, transaction_flags):

def main():
    backend = PackageKitPacmanBackend("", CONF)
    backend.dispatcher(sys.argv[1:])

if __name__ == "__main__":
    main()
