#!/usr/bin/env python

import itertools as it, operator as op, functools as ft
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

	def __setitem__(self, k, v):
		self.db[k] = '\1' + json.encode(v)

	def __del__(self): self.db.close()



def check_fs( path, db,
		hashes=['md5', 'sha1', 'sha512'],
		ignore_mtime=False, bs=2 * 2**20 ):
	from os.path import join, realpath

	if not isinstance(hashes, dict):
		hashes = dict((alg, getattr(hashlib, alg)) for alg in hashes)

	for root, dirs, files in os.walk(path):
		for path in files:
			path = realpath(join(root, path))
			path_mtime = os.stat(path).st_mtime

			meta_update = False
			try: meta = db[path]
			except KeyError: meta, meta_update = dict(), True

			if meta and path_mtime == meta.get('mtime'): continue

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

			if meta_update:
				meta.update(dict(mtime=path_mtime, hashes=src_hashes))
				db[path] = meta


def check_remote(db, remote): pass # TODO


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
	manifest_db = dict(shelve=ManifestShelveDB)[cfg.manifest.type](cfg.manifest)
	for path in cfg.local: check_fs(path, manifest_db, hashes=cfg.manifest.hashes)

	## Check the manifest against remotes
	# TODO
