#!/usr/bin/env python

import itertools as it, operator as op, functools as ft
from time import time
import os, sys, xmlrpclib, hashlib, json


# TODO: aria2-based configurable fetcher
# class Fetcher(object):

# 	def check_mirror():
# 		s = xmlrpclib.ServerProxy('http://localhost:6800/rpc')
# 		s.aria2.addUri(['http://chromeos.hexxeh.net/ChromeOS-Zero.torrent'],{'dir':'/mydownloads'})



class ManifestShelveDB(object):

	def __init__(self, conf):
		import shelve
		self.db = shelve.open(conf.path)

	def __getitem__(self, k):
		v = self.db[k]
		vv, v = v[0], v[1:]
		if vv == '\1': return v
		raise NotImplementedError('Unknown value encoding version: {}'.format(ord(vv)))

	def __setitem__(self, k, meta):
		self.db[k] = '\1' + json.encode(meta)

	def __del__(self): self.db.close()

	def undergoal_order(self, qmin, qmax, limit, mirrors):
		queue = list()
		for path, meta in self.db.viewitems():
			meta_mirrors = meta.get('mirrors', dict())
			prio = dict(
				(mtype, len(set(
					meta_mirrors.get(mtype, set()) ).intersection(mirrors)))
				for mtype in ['inconsistent', 'consistent', 'unavailable'] )
			if prio['consistent'] >= qmax: continue # this one is fine
			# prio = inconsistencies, checks to get qmin, checks to get qmax, known-availability
			prio = prio['inconsistent'], max(0, qmin - prio['consistent']),\
				max(0, qmax - prio['consistent']), -prio['unavailable']
			queue.append((prio, path))
			if len(queue) > limit: break
		return set(it.imap(op.itemgetter(1), sorted(queue)))


def check_fs( path, db,
		hashes=['md5', 'sha1', 'sha512'],
		ignore_mtime=False, bs=2 * 2**20,
		ts=None ):
	from os.path import join, realpath

	if not ts: ts = time()
	if not isinstance(hashes, dict):
		hashes = dict((alg, getattr(hashlib, alg)) for alg in hashes)

	for root, dirs, files in os.walk(path):
		for path in files:
			path = realpath(join(root, path))
			path_mtime = os.stat(path).st_mtime

			try: meta = db[path]
			except KeyError: meta = dict()

			if meta and path_mtime != meta.get('mtime'):
				src_hashes = dict( (alg, func())
					for alg,func in hashes.viewitems() )
				with open(path, 'rb') as src:
					for chunk in iter(ft.partial(src.read, bs), ''):
					for chksum in src_hashes.viewvalues(): chksum.update(chunk)
				meta_hashes = meta.get('hashes', dict())
				for alg,chksum in src_hashes.viewitems():
					chksum = src_hashes[alg] = chksum.hexdigest()
					if alg in meta_hashes:
						if meta_hashes[alg] != chksum:
							log.warn('Detected change in file contents: {}'.format(path))
							meta_update = True
					else: meta_update = True
				meta.update(dict(mtime=path_mtime, hashes=src_hashes))

			meta['ts'] = ts
			db[path] = meta


def check_gc(db, timeout):
	ts_min = time() - timeout
	for k in list( path for path, meta
		in db.viewitems() if meta['ts'] < ts_min ): del db[k]


def check_remote(paths, db, mirrors):
	for path in paths:
		meta = db[path]
		# TODO: from here



def main():
	import argparse
	parser = argparse.ArgumentParser(
		description='Check integrity of mirrored files.')
	parser.add_argument('-c', '--config',
		action='append', metavar='path', default=list(),
		help='Configuration files to process.'
			' Can be specified more than once.'
			' Values from the latter ones override values in the former.'
			' Available CLI options override the values in any config.')
	parser.add_argument('--debug',
		action='store_true', help='Verbose operation mode.')
	optz = parser.parse_args()

	## Read configuration files
	from lya import AttrDict
	cfg = AttrDict.from_yaml('{}.yaml'.format(
		os.path.splitext(os.path.realpath(__file__))[0] ))
	for k in optz.config: cfg.update_yaml(k)

	## Logging
	import logging
	logging.basicConfig(
		logging.WARNING if not optz.debug else logging.DEBUG )

	## Update the manifest
	check_fs_ts = time()
	manifest_db = dict(shelve=ManifestShelveDB)[cfg.manifest.type](cfg.manifest)
	for path in cfg.local:
		check_fs(path, manifest_db, hashes=cfg.manifest.hashes, ts=check_fs_ts)
	## Manifest cleanup
	check_gc(manifest_db, cfg.goal.gc_timeout * 24 * 3600)

	## Build a large-enough list of stuff to be checked
	qratio = int(len(cfg.remote) * cfg.goal.query.ratio)
	qmin = cfg.goal.query.hard_min or qratio
	qmax = max(qmin, cfg.goal.query.hard_max or qratio)
	undergoal = manifest_db.undergoal_order(
		qmin, qmax, limit=cfg.load.limit.files, mirrors=cfg.remote )
	# Check that each listed path actually exists now
	for path in list(undergoal):
		try:
			meta = db[path]
			if meta['ts'] != check_fs_ts and not os.path.exists(path):
				raise KeyError(path)
		except KeyError:
			log.debug('Skipping check for unlisted/nx path: {}'.format(path))
			undergoal.remove(path)

	## Check the manifest against remotes
	check_remote(undergoal, manifest_db, cfg.remote)
