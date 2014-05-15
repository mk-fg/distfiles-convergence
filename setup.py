#!/usr/bin/env python

from setuptools import setup, find_packages
import os

pkg_root = os.path.dirname(__file__)

# Error-handling here is to allow package to be built w/o README included
try: readme = open(os.path.join(pkg_root, 'README.md')).read()
except IOError: readme = ''

setup(

	name = 'distfiles-convergence',
	version = '14.05.0',
	author = 'Mike Kazantsev',
	author_email = 'mk.fraggod@gmail.com',
	license = 'WTFPL',
	keywords = 'distfiles security perspectives'
		' convergence mirrors consistency checksum hash',
	url = 'http://github.com/mk-fg/distfiles-convergence',

	description = 'Tool to verify integrity of the local source'
		' tarballs (or distfiles) by mirror network consensus',
	long_description = readme,

	classifiers = [
		'Development Status :: 4 - Beta',
		'Environment :: Console',
		'Environment :: No Input/Output (Daemon)',
		'Intended Audience :: System Administrators',
		'License :: OSI Approved',
		'Operating System :: POSIX',
		'Programming Language :: Python',
		'Programming Language :: Python :: 2.7',
		'Programming Language :: Python :: 2 :: Only',
		'Topic :: Internet',
		'Topic :: Security',
		'Topic :: System :: Archiving',
		'Topic :: System :: Archiving :: Packaging',
		'Topic :: System :: Monitoring',
		'Topic :: System :: Software Distribution' ],

	install_requires = ['layered-yaml-attrdict-config'],
	extras_require = {
		'remotes.gentoo_portage': ['plumbum'],
		'remotes.rsync': ['plumbum'] },

	packages = find_packages(),
	include_package_data = True,

	package_data = {'distfiles_convergence': ['core.yaml']},
	entry_points = dict(console_scripts=[
		'distfiles-convergence = distfiles_convergence.core:main' ]) )
