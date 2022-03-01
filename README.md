# Pandora

<img src="https://pandora.circl.lu/static/images/logo.svg" width="250" height="250">

Pandora is an analysis framework to discover if a file is suspicious and conveniently show the results.

## Features

- Flexible and open source framework to integrate external tools for checking files.
- A convenient preview module to allow a safe preview for end-users.
- A way to share results on-demand by the end-users.
- Complete standalone open source solution which can allow any organisation to run their own without leaking information or sensitive documents.
- Analysis modules included are [hashlookup](https://github.com/pandora-analysis/pandora/blob/main/pandora/workers/hashlookup.py), [hybridanalysis](https://github.com/pandora-analysis/pandora/blob/main/pandora/workers/hybridanalysis.py), [irma](https://github.com/pandora-analysis/pandora/blob/main/pandora/workers/irma.py), [joesandbox](https://github.com/pandora-analysis/pandora/blob/main/pandora/workers/joesandbox.py), [malwarebazaar](https://github.com/pandora-analysis/pandora/blob/main/pandora/workers/malwarebazaar.py), [msodde](https://github.com/pandora-analysis/pandora/blob/main/pandora/workers/msodde.py), [mwdb](https://github.com/pandora-analysis/pandora/blob/main/pandora/workers/mwdb.py), [ole](https://github.com/pandora-analysis/pandora/blob/main/pandora/workers/ole.py), [virustotal](https://github.com/pandora-analysis/pandora/blob/main/pandora/workers/virustotal.py), [xmldeobfuscator](https://github.com/pandora-analysis/pandora/blob/main/pandora/workers/xmldeobfuscator.py), [yara](https://github.com/pandora-analysis/pandora/blob/main/pandora/workers/yara.py).

# Demo and online public instance

- CIRCL operates a [public instance of pandora](https://pandora.circl.lu/) which can be used for evaluating pandora.

# Install guide

## System dependencies

You need poetry installed, see the [install guide](https://python-poetry.org/docs/).

## Prerequisites

### Redis

You need to have redis cloned and installed in the same directory you clone this template in:
this repoitory and and `redis` must be in the same directory, and **not** `redis` cloned in the
this directory. See [this guide](https://www.lookyloo.eu/docs/main/install-lookyloo.html#_install_redis).

### Kvrocks

The same way you installed redis, you need kvrocks. For that, please follow the [install guide](https://github.com/KvrocksLabs/kvrocks#building-kvrocks).
the kvrocks directory *must* be in the same directory as redis, but *not* in the redis directory.

### Clone pandora

Do the usual:

```bash
git clone https://github.com/pandora-analysis/pandora.git
```

### Ready to install pandora?

And at this point, you should be in a directory that contains `redis`, `kvrocks`, and `pandora`.

Make sure it is the case by running `ls redis kvrocks pandora`. If you see `No such file or directory`,
one of them is missing and you need to fix the installation.

The directory tree must look like that:

```
.
├── redis  => compiled redis
├── kvrocks => compiled kvrocks
└── pandra => not installed pandora yet
```

## Installation

### System dependencies (requires root)

```bash
sudo apt install python3-dev  # for compiling things
sudo apt install libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0  # For HTML -> PDF
sudo apt install libreoffice-base-nogui libreoffice-calc-nogui libreoffice-draw-nogui libreoffice-impress-nogui libreoffice-math-nogui libreoffice-writer-nogui  # For Office -> PDF
sudo apt install exiftool  # for extracting exif information
```

Note: on Ubuntu 20.04, libreoffice-nogui cannot be installed due to some dependencies issues.

### Pandora installation

From the directory you cloned Pandora to, run:

```bash
poetry install
```

Initialize the `.env` file:

```bash
echo PANDORA_HOME="`pwd`" >> .env
```

### Configuration

Copy the config file:

```bash
cp config/generic.json.sample config/generic.json
cp config/workers.yml.sample config/workers.yml
```

And configure it accordingly to your needs.

### Update and launch

Run the following command to fetch the required javascript deps and run pandora.

```bash
poetry run update --yes
```

With the default configuration, you can access the web interface on `http://0.0.0.0:6100`.

# Usage

Start the tool (as usual, from the directory):

```bash
poetry run start
```

You can stop it with

```bash
poetry run stop
```

With the default configuration, you can access the web interface on `http://0.0.0.0:6100`.

# AppArmor and security notes

It is important to keep in mind that Pandora parses and sometimes opens or runs untrusted and
(potentially) malicious content.
One of he most dangerous dependency is libreoffice, which is used to generate the
previews of office documents. By default libreoffice doesn't runs macros, but
as every big piece of software, it has vulnerabilities, known or not.
You absolutely must make sure you always run the most up-to-date version, and keep track of the
security patches. On top of that, there will be 0-days, meaning vulnerabilities lacking
a patch (yet). If they can be exploited against libreoffice used by Pandora,
it could lead to your system being compromised.

Two things you can do to mitigate the risks:

* make sure the machine running Pandora cannot be used to connect to anything internal in your organisation
* enable AppArmor profiles related to libreoffice:

```bash
sudo apt install apparmor-utils  # Installs utils for apparmor
```

Edit `/etc/apparmor.d/usr.lib.libreoffice.program.soffice.bin` and insert:

```
  owner @{HOME}/pandora/tasks/** rwk,
```

Anywhere below this line:

```
profile libreoffice-soffice /usr/lib/libreoffice/program/soffice.bin {
```

And finally, enable the profiles:

```bash
aa-enforce /etc/apparmor.d/usr.lib.libreoffice*
```

# Contributing

Feel free to fork the code, play with it, make some patches and send us the pull requests.

Feel free to contact us, create [issues](https://github.com/pandora-analysis/pandora/issues) if you have questions, remarks or bug reports.

If you have any report concerning security, please read the [SECURITY page](security.md) on how to report security issues and vulnerabilities.

# License

Copyright (C) 2021-2022 [CIRCL](https://www.circl.lu/) - Computer Incident Response Center Luxembourg

Copyright (C) 2018-2022 [CERT-AG](https://cert-ag.com/) - CERT Credit Agricole

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
