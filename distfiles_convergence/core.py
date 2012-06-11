#!/usr/bin/env python

import itertools as it, operator as op, functools as ft
from contextlib import closing
from time import time
from fnmatch import fnmatch
from threading import Event
from tempfile import TemporaryFile
from collections import defaultdict
from os.path import join, realpath, basename, dirname
import os, sys, hashlib, re

try: import simplejson as json
except ImportError: import json


def fnmatch( pattern, name,
		_match=fnmatch, _glob_cbex = re.compile(r'\{[^}]+\}') ):
	'''Shell-like fnmatch with support for curly braces.
		Usage of these braces in the actual name isn't supported.'''
	subs = list()
	while True:
		ex = _glob_cbex.search(pattern)
		if not ex: break
		subs.append(ex.group(0)[1:-1].split(','))
		pattern = pattern[:ex.span()[0]] + '{}' + pattern[ex.span()[1]:]
	return any( _match(name, pat)
		for pat in it.starmap(pattern.format, it.product(*subs)) )


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
	def __delitem__(self, k): del self.db[k]
	def __setitem__(self, k, meta): self.db[k] = '\1' + json.dumps(meta)
	def __del__(self): self.db.close()

	def iteritems(self): return ((k, self.decode(v)) for k,v in self.db.iteritems())

	def undergoal_order(self, qmin, qmax, remotes, limit=None, ts_min=None):
		queue = list()
		for path, meta in self.iteritems():
			if ts_min and meta['ts'] < ts_min: continue
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
			if limit and len(queue) >= limit: break
		return map(op.itemgetter(1), sorted(queue, reverse=True))


def check_fs( path, db,
		hashes=['md5', 'sha1', 'sha512'], bs=2 * 2**20,
		local_changes_warn=True, ts=None, ts_min=None ):
	if not ts: ts = time()
	if not isinstance(hashes, dict):
		hashes = dict((alg, getattr( hashlib,
			alg, ft.partial(hashlib.new, alg) )) for alg in hashes)

	for root, dirs, files in os.walk(path):
		for path in files:
			path = realpath(join(root, path))
			path_mtime = os.stat(path).st_mtime
			if ts_min and path_mtime < ts_min: continue

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
				meta_update = False
				for alg,chksum in src_hashes.viewitems():
					chksum = src_hashes[alg] = chksum.hexdigest()
					if alg in meta_hashes:
						if meta_hashes[alg] != chksum: meta_update = True
					else: meta_update = True
				meta.update(dict(mtime=path_mtime, hashes=src_hashes))
				if meta_update:
					(log.warn if local_changes_warn else log.info)\
						('Detected change in file contents: {}'.format(path))
					meta.pop('remotes', None) # invalidated

			meta['ts'] = ts
			db[path] = meta


def check_gc(db, ts_min):
	for path in list( path for path, meta
			in db.iteritems() if meta['ts'] < ts_min ):
		log.debug('Dropping metadata for path: {}'.format(path))
		del db[path]


class NXError(Exception): pass
class CheckError(Exception): pass


def check_portage(portage, path, hashes, conf,
		_manifest_up2date=Event() ):
	import anydbm

	meta_manifest = conf.meta_manifest\
		.format(hash=hashlib.md5(portage).hexdigest()[:5])

	if not _manifest_up2date.is_set():
		try: meta_manifest_ts = os.stat(meta_manifest).st_mtime
		except OSError: meta_manifest_mtime = 0
		try:
			portage_ts = os.stat(join(
				portage, 'metadata', 'timestamp.chk' )).st_mtime
		except OSError: portage_ts = 0
		if not portage_ts or portage_ts > meta_manifest_ts:
			log.debug( 'Updating combined'
				' portage manifest-db ({})'.format(meta_manifest) )
			from plumbum.cmd import find, xargs
			from plumbum.commands import PIPE
			proc = (
					find[ portage, '-mindepth', '3', '-maxdepth', '3',
						'-name', 'Manifest', '-newert', '@{}'.format(int(meta_manifest_ts)) ]\
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
		_manifest_up2date.set()
		os.utime(meta_manifest, None) # make sure mtime gets bumped

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


def check_rsync(url, path, hashes, conf):
	from plumbum.cmd import rsync
	from plumbum.commands import ProcessExecutionError

	name = basename(path)
	url = ''.join([url, '/' if not url.endswith('/') else '', name])

	err = None
	try: code, stdout, stderr = rsync['--dry-run', '-c', '--out-format=%n', url, path].run()
	except ProcessExecutionError as err: cmd, code, stdout, stderr = err.args

	stdout, stderr = stdout.strip(), stderr.strip()
	if code == 0: return not stdout
	elif code == 23 and re.search( r'\blink_stat'
		r' .* failed: No such file or directory\b', stderr ): raise NXError(name)
	elif err: raise err
	else: raise CheckError('Rsync run failed: {!r}'.format([code, stdout, stderr]))

def check_rsync_batched(url, paths, conf):
	from plumbum.cmd import rsync
	from plumbum.commands import PIPE
	url = ''.join([url, '/' if not url.endswith('/') else '', '.'])
	psg_err, psg_done, psg_nx = set(), set(), set()

	if isinstance(paths, dict): paths = paths.viewitems()
	paths = it.groupby(sorted(
		(path.rsplit(os.sep, 1) + [path])
		for path,hashes in paths ), key=op.itemgetter(0))
	for dst, names in paths:
		names = dict(it.imap(op.itemgetter(1, 2), names))
		ps_err, ps_done, ps_nx = set(), set(), set()
		log.debug('Querying rsync-remote for {} names'.format(len(names)))
		rsync_filter = '\n'.join(map('+ /{}'.format, names) + ['- *', ''])
		with TemporaryFile() as tmp:
			tmp.write(rsync_filter)
			tmp.flush(), tmp.seek(0)
			proc = (rsync[ '--dry-run', '-cr', '-vv',
				'--filter=merge -', url, dst ] < tmp).popen(stdout=PIPE)
			for line in it.imap(op.methodcaller('strip'), proc.stdout):
				if line in names:
					ps_err.add(names[line])
					continue
				match = re.search(r'^(?P<name>.+)\s+is uptodate', line)
				if match:
					name = match.group('name')
					if name not in names:
						log.warn('Detected "uptodate" response for unknown name: {}'.format(name))
					else: ps_done.add(names[name])
					continue
			ps_nx = set(names.viewvalues()).difference(ps_err, ps_done)
			log.debug( 'Rsync stats - inconsistent:'
				' {}, consistent: {}, nx: {}'.format(*it.imap(len, [ps_err, ps_done, ps_nx])) )
			psg_err.update(ps_err), psg_done.update(ps_done), psg_nx.update(ps_nx)
	return psg_err, psg_done, psg_nx


def check_mirror(url, path, hashes, conf): pass


def check_remotes( paths, remotes, db, checks,
		thresh_err=0, thresh_nx=0, thresh_bug=0,
		skip_nx=False, warn_skip=True, skip_remotes=None ):

	if not skip_remotes: skip_remotes = defaultdict(set)
	batched = dict()

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
		#  not-yet-checked mirrors
		#  404 (file wasn't found there before) mirrors
		# Mirrors within each tier are ordered as configured
		rs_ordered = list( remotes[idx]
			for idx in reduce( op.add,
				( sorted(it.imap(remotes.index, rs_set))
					for rs_set in [ rs_err,
						set(remotes).difference(rs_err, rs_done, rs_nx),
						(set(remotes).intersection(rs_nx) if not skip_nx else set()) ] ) ) )
		if not rs_ordered: continue

		log.debug('Querying remotes for path {}: {}'.format(path, rs_ordered))
		for remote in rs_ordered:
			if remote in skip_remotes[path]: continue
			rtype, url = remote

			if '{}__batched'.format(rtype) in checks:
				log.debug('Delaying query for path {!r} into batch: {}'.format(path, remote))
				if remote not in batched: batched[remote] = list()
				batched[remote].append(((path, meta.get('hashes', dict())), rs_ordered))
				break

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

				skip_remotes[path].add(remote)

		meta['remotes'] = dict(it.izip([ 'inconsistent',
			'consistent', 'unavailable' ], it.imap(list, [rs_err, rs_done, rs_nx])))
		db[path] = meta

	if batched:
		tails = list()
		for remote, paths in batched.viewitems():
			rtype, url = remote
			rpaths = dict(it.imap(op.itemgetter(0), paths))
			ps_err, ps_done, ps_nx = checks['{}__batched'.format(rtype)](url, rpaths)
			for path in rpaths:
				meta = db[path]
				for k, ps in [('inconsistent', ps_err), ('consistent', ps_done), ('unavailable', ps_nx)]:
					if path in ps: meta['remotes'][k] = list(set(meta['remotes'][k]).union([remote]))
				db[path] = meta
				skip_remotes[path].add(remote)
			tails.extend(rpaths)

		# Recursive call to process the rest of the remotes
		check_remotes( tails, remotes, db, checks,
			thresh_err=thresh_err, thresh_nx=thresh_nx, thresh_bug=thresh_bug,
			skip_nx=skip_nx, warn_skip=warn_skip, skip_remotes=skip_remotes )



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
	parser.add_argument('-m', '--mtime-after',
		type=int, metavar='unix_time',
		help='Only act on files with'
			' mtime larger than the given value (unix timestamp).')
	parser.add_argument('-l', '--list', nargs='?', metavar='types', default=False,
		help='Instead of usual action, just dump current state of all the files and exit.'
			'Can take an optional "type" (of mirrors wrt file) argument (comma-separated type(s)):'
				' consistent, inconsistent, unavailable, undergoal (default: inconsistent, unavailable).')
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
		(k, ft.partial(v, conf=cfg.checks.get(k.split('__', 1)[0], dict())))
		for k,v in dict( gentoo_portage=check_portage,
			rsync=check_rsync, rsync__batched=check_rsync_batched,
			mirrors=check_mirror ).viewitems() )

	## Catch-up with local fs
	check_fs_ts = time()
	manifest_db = modules_manifest_db[cfg.manifest.type](cfg.manifest)
	log.debug('Updating manifest-db with hashes of local files')
	for path in cfg.local:
		check_fs( path, manifest_db, hashes=cfg.manifest.hashes,
			local_changes_warn=cfg.goal.warn.local_changes,
			ts=check_fs_ts, ts_min=optz.mtime_after )
	log.debug('Manifest-db cleanup')
	ts_gc_min = check_fs_ts - cfg.goal.gc_timeout * 24 * 3600
	if optz.mtime_after and optz.mtime_after < ts_gc_min:
		check_gc(manifest_db, ts_min=ts_gc_min)

	## List of remotes in order of preference
	remotes = list()
	for rtype, urls in cfg.remote.viewitems():
		for url in urls or list(): remotes.append((rtype, url))

	## Build a set of excluded filename-patterns
	exclude = set(cfg.exclude.patterns or set())
	for src in cfg.exclude.from_files or list():
		with open(src, 'rb') as src:
			for pat in it.ifilter( None,
					it.imap(op.methodcaller('strip'), src) ):
				exclude.add(pat)

	## Build a large-enough list of stuff to be checked
	qratio = int(len(remotes) * cfg.goal.query.ratio)
	qmin = min(len(remotes), cfg.goal.query.hard_min or qratio)
	qmax = min(len(remotes), max(qmin, cfg.goal.query.hard_max or qratio))
	limit = (cfg.goal.limit.files or None) if not optz.list else None
	undergoal = manifest_db.undergoal_order(
		qmin, qmax, limit=limit,
		remotes=remotes, ts_min=optz.mtime_after )
	# Check that each listed path actually exists now and isn't conf-excluded
	drop = set()
	for path in undergoal:
		for pat in exclude:
			if fnmatch(pat, basename(path)):
				drop.add(path)
				continue
		try:
			meta = manifest_db[path]
			if meta['ts'] != check_fs_ts and not os.path.exists(path):
				raise KeyError(path)
		except KeyError:
			log.debug('Skipping check for unlisted/nx path: {}'.format(path))
			drop.add(path)
	undergoal = list(path for path in undergoal if path not in drop)

	## Just dump the list, if requested
	if optz.list is not False:
		log.debug('Just listing all the remotes')
		if not optz.list: optz.list = 'inconsistent, unavailable'
		mtypes = sorted(it.imap(op.methodcaller('strip'), optz.list.split(',')))
		mtypes_err = set(mtypes).difference([
			'consistent', 'inconsistent', 'unavailable', 'undergoal' ])
		if mtypes_err:
			parser.error('Unrecognized check states: {}'.format(', '.join(mtypes_err)))
		if 'undergoal' in mtypes:
			undergoal_check = True
			mtypes = sorted(
				set(mtypes).difference(['undergoal'])\
					.union(['consistent', 'inconsistent', 'unavailable']) )
		else: undergoal_check = False
		for path in undergoal:
			meta_remotes = manifest_db[path].get('remotes', dict())
			if undergoal_check and not (
				len(set(meta_remotes.get(
					'consistent', set() )).intersection(remotes)) < qmin\
				or set(meta_remotes.get(
					'inconsistent', set() )).intersection(remotes) ): continue
			if not meta_remotes:
				print('Path: {}\n  No consistency data available'.format(path))
				continue
			path_line = False
			for mtype in mtypes:
				mtype_remotes = set(meta_remotes.get(mtype, set())).intersection(remotes)
				if not mtype_remotes: continue
				if not path_line:
					print('Path: {}'.format(path))
					path_line = True
				print('  {}{}'.format(mtype, ' ({}{}):\n    {}'.format(
					len(mtype_remotes), ''
						if mtype != 'consistent' else ', min/max: {}/{}'.format(qmin, qmax),
					'\n    '.join(it.starmap('({}) {}'.format, sorted(mtype_remotes))) )))
		sys.exit()

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
