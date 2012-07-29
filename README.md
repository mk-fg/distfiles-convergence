distfiles-convergence
--------------------

"It's not just an academic issue.
Now a days, every blackhat and their mother has owned a major distfile mirror,
and it's something of a weekend sport to own the smaller more obscure distros
and trojan their OpenSSH.
It's a real threat. It's happening now; it's part of the world we live in."
 -- [zx2c4](http://article.gmane.org/gmane.linux.distributions.exherbo.devel/1072)

A simple tool to verify integrity of the local source tarballs or distfiles (as
they're called in source-based systems like gentoo or freebsd) by comparing
them to another mirrors and available manifests, seeking consensus.


Usage
--------------------

All the local paths and remote URLs are specified in the [configuration
file](https://github.com/mk-fg/distfiles-convergence/blob/master/distfiles_convergence/core.yaml).

Since several configuration files can be specified (each later one overidding
corresponding values in the former), it's recommended never to touch the shipped
original file (which gets read automatically) and just create a simplier config,
overriding what's necessary, for example:

	local:
		- /srv/distfiles

	remote:
		gentoo_portage:
			- /usr/portage
		rsync:
			- rsync://mirror.netcologne.de/gentoo/distfiles/
			- rsync://rsync.mirrorservice.org/www.ibiblio.org/gentoo/
			- rsync://gentoo.mirrors.tds.net/gentoo/distfiles/
			- rsync://trumpetti.atm.tut.fi/gentoo/distfiles/
			- rsync://gentoo.gossamerhost.com/gentoo-distfiles/distfiles/

	goal:
		query:
			ratio: 0.7
			hard_min: 2
			hard_max: 5

	exclude:
		from_files:
			- /var/lib/dc/exclude.txt

	manifest:
		type: dbm
		path: /var/lib/dc/distfiles.db

	checks:
		gentoo_portage:
			meta_manifest: /var/lib/dc/portage.{hash}.db

When that put as, say, `/etc/dc.yaml`, check can be ran as:

	% distfiles-convergence -c /etc/dc.yaml

Use "--debug" option to see what it's actually doing there.
See [baseline configuration
file](https://github.com/mk-fg/distfiles-convergence/blob/master/distfiles_convergence/core.yaml)
for the full list of available options and their descriptions.

Upon start, app will checksum distfiles in "local" path, then go over "remote"
sources in the order in which they're specified, comparing checksums (or files,
in case of rsync mirrors, since it's generally less traffic and load than full
download and checksum), trying to meet specified "goal" (in this particular
config - match against 2-5 or 70% of specified mirrors).

There are some more subtleties in the process, but basically it's just that.


Installation
--------------------

It's a regular package for Python 2.7 (not 3.X), but not in pypi, so can be
installed from a checkout with something like that:

	% python setup.py install

Note that to install stuff in system-wide PATH and site-packages, elevated
privileges are often required.
Use
[~/.pydistutils.cfg](http://docs.python.org/install/index.html#distutils-configuration-files)
or [virtualenv](http://pypi.python.org/pypi/virtualenv) to do unprivileged
installs into custom paths.

Better way would be to use [pip](http://pip-installer.org/) to install all the
necessary dependencies as well:

	% pip install 'git://github.com/mk-fg/distfiles-convergence.git#egg=distfiles-convergence'

Alternatively, `./distfiles-convergence` can be run right from the checkout tree,
without any installation.

### Requirements

* Python 2.7 (not 3.X)
* [layered-yaml-attrdict-config](https://github.com/mk-fg/layered-yaml-attrdict-config)
* [plumbum](http://plumbum.readthedocs.org/) to work with rsync and
  gentoo_portage mirrors


Mirror types
--------------------

### Gentoo Portage

Gentoo portage tree contains "Manifest" files with several strong checksums for
each distfile. Package managers (portage and paludis) use and check these, so
they also get quite a lot of review from different network perspectives.

These Manifests can be easily used, as well as the similar Manifest files from
any gentoo overlay.
Keeping local tree (or overlays) in sync with the upstream is outside the scope
of this app though (but can be done with a simple cronjob).

For the list of available gentoo portage tree mirrors, see
http://www.gentoo.org/main/en/mirrors-rsync.xml

### Rsync mirrors

These are more efficient traffic-wise than regular http(s) or ftp mirrors,
because rsync on the server can cooperate with local rsync and just
calculate/compare the local/remote checksums.

Also, requests for checks on rsync mirrors get batched into a single
connection/run, to reduce the load on the mirrors.

List of rsync mirrors (among others) can be found here, for instance:
http://www.gentoo.org/main/en/mirrors2.xml
