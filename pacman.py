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

from packagekit.enums import *
from pyalpm import *
from pycman.config import *
import re

CONF = '/etc/pacman.conf'

def pacman(conf=None):
    config = PacmanConfig(conf)
    handle = config.initialize_alpm()
    return Pacman(handle)

class PkgFilter:
    def __init__(self, filters=None):
        self.filters = filters

    def filter(self, pkgs):
        filters = self.filters
        if FILTER_INSTALLED in filters:
            pkgs = self.filter_install(pkgs, 1)
        elif FILTER_NOT_INSTALLED in filters:
            pkgs = self.filter_install(pkgs, 0)

        if FILTER_FREE in filters:
            pkgs = self.filter_free(pkgs, 1)
        elif FILTER_NOT_FREE in filters:
            pkgs = self.filter_free(pkgs, 0)

        if FILTER_NEWEST in filters:
            pkgs = self.filter_newest(pkgs, 1)
        return pkgs

    def filter_install(self, pkgs, flag=1):
        ou = []
        for p in pkgs:
            c = p.db.name == 'local'
            if c == flag:
                ou.append(p)
        return ou

    def filter_free(self, pkgs, flag=1):
        ou = []
        for p in pkgs:
            c = not re.search('custom','&'.join(p.licenses))
            if c == flag:
                ou.append(p)
        return ou

    def filter_newest(self, pkgs, flag=1):
        def _pcm(p0, dc):
            try:
                pkgs = dc[p0.name]
                for i,p in enumerate(pkgs):
                    c0 = vercmp(p0.version, p.version)
                    if c0 != 0:
                        c1 = p0.db.name == 'local'
                        c2 = p.db.name == 'local'
                        if c1 == c2:
                            if c0 != 1:
                                return
                            pkgs.pop(i)
                        pkgs.append(p0)
            except KeyError as e:
                dc[p0.name] = [p0]
        
        dc = dict()
        for p in pkgs:
            _pcm(p, dc)
        ou = []
        for v in dc.values():
            ou += v
        return ou

class PkgCache(object):
    def __init__(self, handle):
        self.handle = handle
        self.repos = [handle.get_localdb()] + handle.get_syncdbs()
        self._trash = []

    def cached(func):
        def _filter(*args, **kwargs):
            cached = set()
            for pkg in func(*args, **kwargs):
                if not (pkg.name, pkg.version) in cached:
                    if pkg.db.name == 'local':
                        cached.add((pkg.name, pkg.version))
                    yield pkg
        return _filter

    @cached
    def all(self):
        for db in self.repos:
            for pkg in db.pkgcache:
                yield pkg

    def set(self, rid, enable):
        def _swp(db, tb):
            tb[1].append(db)
            tb[0].remove(db)
        
        tb = [self.repos, self._trash]
        if enable: tb.reverse()
        for db in tb[0]:
            if db.name == 'rid':
                _swp(db, tb)
                break

    @cached
    def get(self, key):
        for db in self.repos:
            pkg = db.get_pkg(key)
            if not pkg:
                continue
            yield pkg
    
    def dbs(self):
        return self.repos

    def local(self):
        c = PkgCache(self.handle)
        c.repos = self.repos[:1]
        return c
    
    def online(self):
        c = PkgCache(self.handle)
        c.repos.pop(0)
        return c

    def repo(self, repo=None):
        c = PkgCache(self.handle)
        for db in self.repos:
            if db.name == repo:
                c.repos = [db]
                break
        return self

    def newest(self, key):
        if not type(key) == Package:
            key = self.first(key)
        if key:
            nkey = sync_newversion(key, self.handle.get_syncdbs())
            if not nkey:
                return key
            return nkey
    
    @cached
    def provide(self, keys):
        for pkg in self.all():
            flag = True
            for info in pkg.provides:
                for key in keys:
                    if not key in info:
                        flag = False
                        break
                if flag:
                    yield pkg

    def first(self, key, pexprs=None):
        for pkg in self.pkgs(key, pexprs):
            return pkg
    
    @cached
    def pkgs(self, key, pexprs=None):
        '''return the proper pkgs.'''
        def _vcmp(v1, v2):
            r = {-1:'<', 0:'=', 1:'>'}
            return r[vercmp(v1, v2)]
    
        pkgs = self.get(key)
        if pexprs == None or pexprs == []:
            for pkg in pkgs:
                yield pkg
    
        for pkg in pkgs:
            flag = True
            for pexpr in pexprs:
                if pexpr == ():
                    continue
                if not _vcmp(pkg.version, pexpr[1]) in pexpr[0]:
                    flag = False
                    break
            if flag:
                yield pkg

    @cached
    def groups(self, groups):
        for db in self.repos:
            for grp in groups:
                pgrp = db.read_grp(grp)
                if pgrp:
                    for pkg in pgrp[1]:
                        yield pkg

    @cached
    def search(self, keys):
        ss = "|".join(keys)
        for db in self.repos:
            pkgs = db.search(ss)
            if pkgs == []:
                continue
            for pkg in pkgs:
                yield pkg

    @cached
    def match(self, keys):
        for pkg in self.all():
            flag = True
            for key in keys:
                if not re.search(key, pkg.name, re.IGNORECASE):
                    flag = False
                    break
            if flag:
                yield pkg

    def refresh(self, force=False):
        for db in self.online().dbs():
            db.update(force)

class Pacman(object):
    def __init__(self, conf):
        self.config = PacmanConfig(conf)
        self.handle = self.config.initialize_alpm()
        self.source = PkgCache(self.handle)

    def cache(self):
        return self.source

    def _match(self, keys, val):
        for key in keys:
            if key in val:
                return True
        return False
        ret = True
        for key in keys:
            if not key in val:
                ret = False
        return ret

    def dependency(func):
        def _dependency(self, pkg, recursive=True):
            def _format(exprs):
                rr = re.compile(r'<=|>=|<|>|=')
                pexprs = dict()
                for expr in exprs:
                    op = rr.search(expr)
                    if not op:
                        pexprs[expr] = []
                    if op:
                        op = op.group()
                        name, ver = expr.split(op)
                        if not name in pexprs.keys():
                            pexprs[name] = []
                        pexprs[name].append((op, ver))
                return pexprs

            def _package(c, pkgs, out, recursive = True):
                def _dep(pkgs):
                    ou = []
                    for pkg in pkgs:
                        ou += func(pkg)
                    return set(ou)

                def _get(pkes):
                    deps = []
                    for key, val in pkes.items():
                        pkg = c.first(key, val)
                        if pkg:
                            deps.append(pkg)
                    return deps

                deps = _get(_format(_dep(pkgs)))
                if len(deps) < 1:
                    return
                for dep in deps:
                    out.add((dep.name, dep.version, dep.arch, dep.db.name))
                ddeps = _get(_format(_dep(deps)))
                if recursive:
                    ou = set()
                    for ddep in ddeps:
                        ou.add((ddep.name, ddep.version, ddep.arch, ddep.db.name))
                    ou -= out
                    if len(ou):
                        _package(c, ddeps, out, recursive)
            
            c = self.cache()
            out = set()
            _package(c, [pkg], out, recursive)
            rt = []
            for o in out:
                rt.append(c.repo(o[3]).first(o[0], [('=', o[1])]))
            return rt
        return _dependency

    @dependency
    def calc_dependson(pkg):
        return pkg.depends

    @dependency
    def calc_requiredby(pkg):
        return pkg.compute_requiredby()

    def transaction(fn=None, flags=dict()):
        def _transaction(func):
            def commit(self, pkgs, cflags=dict()):
                tr = func(self.handle, cflags)
                print(pkgs,cflags,tr,self.handle.cachedirs)
                try:
                    trans = self.handle.init_transaction(**tr['flags'])
                    for pkg in pkgs:
                        tr['action'](trans, pkg)
                    trans.prepare()
                    trans.commit()
                finally:
                    trans.release()
                    self.handle.cachedirs = ['/var/cache/pacman/pkg/']
            return commit
        if not fn:
            return _transaction
        return _transaction(fn)

    @transaction
    def install(handle, cflags):
        def _cmd(trans, pkg):
            trans.add_pkg(pkg)
        return {'flags':{'force':True, 'needed':True}, 'action':_cmd}

    @transaction
    def remove(handle, cflags):
        def _cmd(trans, pkg):
            trans.remove_pkg(pkg)
        flags = {'cascade':True, 'unneeded':True}
        if 'recurse' in cflags.keys():
            flags['recurse'] = cflags['recurse']
        return {'flags':flags, 'action':_cmd}

    @transaction
    def update(handle, cflags):
        def _cmd(trans, pkg):
            co = self.cache()
            npk = co.newest(pkg)
            if npk:
                trans.add_pkg(npk)
        return {'flags':{'need':True}, 'action':_cmd}

    @transaction
    def download(handle, cflags):
        def _cmd(trans, pkg):
            trans.add_pkg(pkg)
        if 'directory' in cflags.keys():
            handle.cachedirs = [cflags['directory']]
        return {'flags':{'force':True, 'downloadonly':True}, 'action':_cmd}

'''
def cb(fn):
    def _cb(name, trans, tol):
        if trans - _cb.itrans > 32:
            fn(name, trans, tol)
        _cb.itrans = trans
    _cb.itrans = 0
def dlcb(name, trans, tol):
    print(name, trans, tol)
    itrans = trans
p._handle.dlcb = dlcb
'''
#p.install(li)
#p._handle.remove_cachedir('/var/cache/pacman/pkg')
#p._handle.add_cachedir('/home/luxck/')
#print(p._handle.cachedirs)
pcm = Pacman('/etc/pacman.conf')
pk = pcm.cache().online().first('yelp')
#pcm.download([pk],{'directory':'/home/luxck'})
#pcm.remove([pk],{'recurse':True})
#pcm.install([pk])
