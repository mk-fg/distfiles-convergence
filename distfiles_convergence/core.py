#!/usr/bin/env python

import itertools as it, operator as op, functools as ft
from contextlib import closing
from time import time
from os.path import join, realpath, basename
import os, sys, hashlib, json


class ManifestDBM(object):

	def __init__(self, conf):
		import anydbm
		self.db = anydbm.open(conf.path, 'c')

	def decode(self, v):
		vv, v = v[0], v[1:]
		if vv == '\1':
			v = json.loads(v)
			# JSON doesn't have tuples, hence this
			remotes = v.get('remotes', dict())
			for k,rs in remotes.viewitems():
				remotes[k] = map(tuple, rs)
			return v
		raise NotImplementedError('Unknown value encoding version: {}'.format(ord(vv)))

	def __getitem__(self, k): return self.decode(self.db[k])
	def __setitem__(self, k, meta): self.db[k] = '\1' + json.dumps(meta)
	def __del__(self): self.db.close()

	def iteritems(self): return ((k, self.decode(v)) for k,v in self.db.iteritems())

	def undergoal_order(self, qmin, qmax, limit, remotes):
		queue = list()
		for path, meta in self.iteritems():
			meta_remotes = meta.get('remotes', dict())
			prio = dict(
				(mtype, len(set(
					meta_remotes.get(mtype, set()) ).intersection(remotes)))
				for mtype in ['inconsistent', 'consistent', 'unavailable'] )
			if prio['consistent'] >= qmax: continue # this one is fine
			# prio = inconsistencies, checks to get qmin, checks to get qmax, known-availability
			prio = prio['inconsistent'], max(0, qmin - prio['consistent']),\
				max(0, qmax - prio['consistent']), -prio['unavailable']
			queue.append((prio, path))
			if limit and len(queue) > limit: break
		return map(op.itemgetter(1), sorted(queue, reverse=True))


def check_fs( path, db,
		hashes=['md5', 'sha1', 'sha512'],
		ignore_mtime=False, bs=2 * 2**20,
		ts=None, local_changes_warn=True ):
	if not ts: ts = time()
	if not isinstance(hashes, dict):
		hashes = dict((alg, getattr( hashlib,
			alg, ft.partial(hashlib.new, alg) )) for alg in hashes)

	for root, dirs, files in os.walk(path):
		for path in files:
			path = realpath(join(root, path))
			path_mtime = os.stat(path).st_mtime

			try: meta = db[path]
			except KeyError: meta = dict()

			if meta and path_mtime != meta.get('mtime'):
				src_hashes = dict( (alg, func())
					for alg,func in hashes.viewitems() )
				log.debug('Generating checksums for path: {}'.format(path))
				with open(path, 'rb') as src:
					for chunk in iter(ft.partial(src.read, bs), ''):
						for chksum in src_hashes.viewvalues(): chksum.update(chunk)
				meta_hashes = meta.get('hashes', dict())
				for alg,chksum in src_hashes.viewitems():
					chksum = src_hashes[alg] = chksum.hexdigest()
					if alg in meta_hashes:
						if meta_hashes[alg] != chksum:
							(log.warn if local_changes_warn else log.info)\
								('Detected change in file contents: {}'.format(path))
							meta_update = True
					else: meta_update = True
				meta.update(dict(mtime=path_mtime, hashes=src_hashes))

			meta['ts'] = ts
			db[path] = meta


def check_gc(db, timeout):
	ts_min = time() - timeout
	for path in list( path for path, meta
			in db.iteritems() if meta['ts'] < ts_min ):
		log.debug('Dropping metadata for path: {}'.format(path))
		del db[path]


class NXError(Exception): pass

def check_portage(portage, path, hashes, conf):
	import anydbm

	meta_manifest = conf.meta_manifest\
		.format(hash=hashlib.md5(portage).hexdigest()[:5])
	try: meta_manifest_mtime = os.stat(meta_manifest).st_mtime
	except OSError: meta_manifest_mtime = 0
	if os.stat(join(portage, 'metadata', 'timestamp.chk')).st_mtime > meta_manifest_mtime:
		from plumbum.cmd import find, xargs
		from plumbum.commands import PIPE
		proc = (
				find[portage, '-mindepth', '3', '-maxdepth', '3', '-name', 'Manifest']\
				| xargs['-n100', '--no-run-if-empty', 'grep', '--no-filename', '^DIST ']
			).popen(stdout=PIPE)
		with closing(anydbm.open(meta_manifest, 'c')) as mdb:
			for line in proc.stdout:
				dist, name, size, line_hashes = line.split(None, 3)
				assert dist == 'DIST'
				line_hashes = iter(line_hashes.strip().split())
				while True:
					try: k,v = next(line_hashes), next(line_hashes)
					except StopIteration: break
					mdb['{}:{}'.format(k.lower(), name)] = v
		proc.wait()

	name = basename(path)
	with closing(anydbm.open(meta_manifest, 'r')) as mdb:
		match = False
		for alg,chksum in hashes.viewitems():
			try:
				mdb_chksum = mdb['{}:{}'.format(alg, name)]
				if mdb_chksum == chksum:
					match = True
					continue
			except KeyError: continue
			log.info( 'Inconsistency b/w checksums'
				' (type: {}) - mdb: {}, local: {}'.format(alg, mdb_chksum, chksum) )
			return False # checksum inconsistency
		if not match: raise NXError(name)
		return True # at least one match found and no mismatches

def check_rsync(url, path, hashes, conf): pass
def check_mirror(url, path, hashes, conf): pass

def check_remotes( paths, remotes, db, checks,
		thresh_err=0, thresh_nx=0, thresh_bug=0,
		skip_nx=False, warn_skip=True ):
	for path in paths:
		meta = db[path]
		rs = meta.get('remotes', dict())
		rs_err, rs_done, rs_nx = ( set(rs.get(k, set()))
			for k in ['inconsistent', 'consistent', 'unavailable' ] )

		# Get rid of dont-care-about-anymore remotes
		rs_err.intersection_update(remotes)
		rs_nx.intersection_update(remotes)

		# Order is fixed as tiers:
		#  previously-inconsistent mirrors
		#  non-404 mirrors
		#  404 (file wasn't found there before) mirrors
		# Mirrors within each tier are ordered as configured
		rs_ordered = list( remotes[idx]
			for idx in reduce( op.add,
				( sorted(it.imap(remotes.index, rs_set))
					for rs_set in [ rs_err,
						set(remotes).difference(rs_nx, rs_err),
						(set(remotes).intersection(rs_nx) if not skip_nx else set()) ] ) ) )
		if not rs_ordered: continue

		log.debug('Querying remotes for path {}: {}'.format(path, rs_ordered))
		for remote in rs_ordered:
			rtype, url = remote
			try: match = checks[rtype](url, path, meta.get('hashes', dict()))
			except NXError:
				(log.warn if thresh_nx else log.info)\
					('Path {!r} not found on remote {!r}'.format(path, remote))
				rs_nx.add(remote)
			except Exception as err:
				log.error('Failed to match remote {!r} and path {!r}: {}'.format(remote, path, err))
				thresh_bug -= 1
				if thresh_bug < 0: raise
			else:
				if match is False:
					rs_err.add(remote)
					(log.warn if len(rs_err) >= thresh_err else log.info)\
						( 'Detected inconsistency between'
							' remote {!r} and path {!r}'.format(remote, path) )
				elif match: rs_done.add(remote)
				else:
					(log.warn if warn_skip else log.info)\
						('Skipped check Remote: {!r}, path: {!r}'.format(remote, path))

		meta['remotes'] = dict(it.izip([ 'inconsistent',
			'consistent', 'unavailable' ], it.imap(list, [rs_err, rs_done, rs_nx])))
		db[path] = meta



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
	parser.add_argument('-n', '--skip-nx',
		action='store_true', help='Do not retry known-404 mirrors.')
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
		level=logging.WARNING if not optz.debug else logging.DEBUG )
	global log
	log = logging.getLogger()

	## Modules
	modules_manifest_db = dict(dbm=ManifestDBM)
	modules_remote = dict(
		(k, ft.partial(v, conf=cfg.checks.get(k, dict())))
		for k,v in dict( gentoo_portage=check_portage,
			rsync=check_rsync, mirrors=check_mirror ).viewitems() )

	## Catch-up with local fs
	check_fs_ts = time()
	manifest_db = modules_manifest_db[cfg.manifest.type](cfg.manifest)
	log.debug('Updating manifest-db with hashes of local files')
	for path in cfg.local:
		check_fs( path, manifest_db, hashes=cfg.manifest.hashes,
			ts=check_fs_ts, local_changes_warn=cfg.goal.warn.local_changes )
	log.debug('Manifest-db cleanup')
	check_gc(manifest_db, cfg.goal.gc_timeout * 24 * 3600)

	## List of remotes in order of preference
	remotes = list()
	for rtype, urls in cfg.remote.viewitems():
		for url in urls or list(): remotes.append((rtype, url))

	## Build a large-enough list of stuff to be checked
	qratio = int(len(remotes) * cfg.goal.query.ratio)
	qmin = min(len(remotes), cfg.goal.query.hard_min or qratio)
	qmax = min(len(remotes), max(qmin, cfg.goal.query.hard_max or qratio))
	undergoal = manifest_db.undergoal_order(
		qmin, qmax, limit=cfg.goal.limit.files or None, remotes=remotes )
	# Check that each listed path actually exists now
	drop = set()
	for path in undergoal:
		try:
			meta = manifest_db[path]
			if meta['ts'] != check_fs_ts and not os.path.exists(path):
				raise KeyError(path)
		except KeyError:
			log.debug('Skipping check for unlisted/nx path: {}'.format(path))
			drop.add(path)
	undergoal = list(path for path in undergoal if path not in drop)

	## Check against remotes
	log.debug('Checking manifest-db against remotes')
	check_remotes(
		undergoal, remotes, manifest_db, modules_remote,
		thresh_err=min( cfg.goal.warn.inconsistency.max,
			int(len(remotes) * cfg.goal.warn.inconsistency.ratio) ),
		thresh_nx=cfg.goal.warn.unavailable, thresh_bug=cfg.goal.limit.errors,
		skip_nx=optz.skip_nx, warn_skip=cfg.goal.warn.skipped_remote )

	log.debug('Done')


if __name__ == '__main__': main()
