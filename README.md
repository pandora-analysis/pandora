
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/pandora-analysis/pandora/badge)](https://api.securityscorecards.dev/projects/github.com/pandora-analysis/pandora)


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

Note that is is *strongly* recommended to use Ubuntu 22.04, which comes with a more recent of libreoffice.
Using anything older will result in annoying issues when restarting the service: libreoffice
isn't always stopped properly and it results in dead processes using 100% CPU.

## System dependencies

You need poetry installed, see the [install guide](https://python-poetry.org/docs/).

## Prerequisites

### Redis

[Redis](https://redis.io/): An open source (BSD licensed), in-memory data structure store, used as a database, cache and message broker.

NOTE: Redis should be installed from the source, and the repository must be in the same directory as the one you will be cloning Pandora into.

In order to compile and test redis, you will need a few packages:

```bash
sudo apt-get update
sudo apt install build-essential tcl
```

```bash
git clone https://github.com/redis/redis.git
cd redis
git checkout 6.2
make
# Optionally, you can run the tests:
make test
cd ..
```

### Kvrocks

[Kvrocks](https://github.com/apache/incubator-kvrocks) is a distributed key value NoSQL database that uses RocksDB as storage engine and is compatible with Redis protocol.
Kvrocks intends to decrease the cost of memory and increase the capability while compared to Redis.

NOTE: Kvrocks should be installed from the source, and the repository must be in the same directory as the one you will be cloning Pandora into.

In order to compile kvrocks, you will need a few packages:

```bash
sudo apt-get update
sudo apt install git gcc g++ make cmake autoconf automake libtool python3 libssl-dev
```

```bash
git clone --recursive https://github.com/apache/incubator-kvrocks.git kvrocks
cd kvrocks
git checkout 2.4
./x.py build
cd ..
```

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
└── pandora => not installed pandora yet
```

## Installation

### System dependencies (requires root)

```bash
sudo apt install python3-dev  # for compiling things
sudo apt install libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0  # For HTML -> PDF
sudo apt install libreoffice-base-nogui libreoffice-calc-nogui libreoffice-draw-nogui libreoffice-impress-nogui libreoffice-math-nogui libreoffice-writer-nogui  # For Office -> PDF
sudo apt install exiftool  # for extracting exif information
sudo apt install unrar  # for extracting rar files
sudo apt install libxml2-dev libxslt1-dev antiword unrtf poppler-utils pstotext tesseract-ocr flac ffmpeg lame libmad0 libsox-fmt-mp3 sox libjpeg-dev swig  # for textract
sudo apt install libssl-dev  # seems required for yara-python
sudo apt install libcairo2-dev  # Required by reportlab
```

Note: on Ubuntu 20.04, libreoffice-nogui cannot be installed due to some dependencies issues.

### Important notes regarding libreoffice

Some have issues when generating previews. It seems to be related to the version of libreoffice in the packages, and the headless version (`*-nogui` packages) that are sometimes failing. If you see error messages in the logs, install libreoffice from the PPA:

```bash
sudo add-apt-repository ppa:libreoffice/ppa
sudo apt-get update
sudo apt-get install libreoffice
```

### Pandora installation

From the directory you cloned Pandora to, run:

```bash
cd pandora  # if you're not already in the directory
poetry install
```

Initialize the `.env` file:

```bash
echo PANDORA_HOME="`pwd`" >> .env
```

Get web dependencies (css, font, js)
```bash
poetry run python tools/3rdparty.py
```
Be aware that those are version-constrained because [SubResource Integrity (SRI)](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity) is used (set in website/web/sri.txt).

### Configuration

Copy the config file:

```bash
cp config/generic.json.sample config/generic.json
```

And configure it accordingly to your needs.

### Antivirus workers

#### ClamAV

Install the package from the official repositories, and the default config will work out of the box:

```bash
sudo apt-get install clamav-daemon
# In order for the module to work, you need the signatures.
# Running the command "freshclam" will do it but if the script is already running
# (it is started by the systemd service clamav-freshclam)
# You might want to run the commands below:
sudo systemctl stop clamav-freshclam.service  # Stop the service
sudo freshclam  # Run the signatures update
sudo systemctl start clamav-freshclam.service # Start the service so we keep getting the updates
```

Then, check if `/var/run/clamav/clamd.ctl` exists. If it doesn't, start the service:

```bash
sudo service clamav-daemon start
```

#### Comodo

Install it from the official website:

```bash
wget https://download.comodo.com/cis/download/installs/linux/cav-linux_x64.deb
sudo dpkg --ignore-depends=libssl0.9.8 -i cav-linux_x64.deb
```

As we need X session to download the database automatically, the easiest on a server is to
do it manually from the [official website](https://www.comodo.com/home/internet-security/updates/vdp/database.php).

```bash
sudo wget http://cdn.download.comodo.com/av/updates58/sigs/bases/bases.cav -O /opt/COMODO/scanners/bases.cav
```

Best way to keep your Database up-to-date is to create a cron running it.

In case of error during the next upgrade of the system, edit `/var/lib/dpkg/status`
and remove the dependencies for cav-linux packages.

### Workers configuration

Copy the sample config files (`<workername>.yml.sample`) and edit the newly created ones (`<workername>.yml`):

```bash
for file in pandora/workers/*.sample; do cp -i ${file} ${file%%.sample}; done
```

Configure them accordingly to your needs (API key, file paths, ...).

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
One of the most dangerous dependency is libreoffice, which is used to generate the
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

# Notes & issues

If you're getting a stacktrace that look like that:

```
Fatal exception: Signal 6
Stack:
/usr/lib/libreoffice/program/libuno_sal.so.3(+0x3ffc3)[0x7f80bb86ffc3]
/usr/lib/libreoffice/program/libuno_sal.so.3(+0x4013a)[0x7f80bb87013a]
/lib/x86_64-linux-gnu/libc.so.6(+0x43090)[0x7f80bb675090]
/lib/x86_64-linux-gnu/libc.so.6(gsignal+0xcb)[0x7f80bb67500b]
/lib/x86_64-linux-gnu/libc.so.6(abort+0x12b)[0x7f80bb654859]
/usr/lib/libreoffice/program/libmergedlo.so(+0x1219b92)[0x7f80bcab2b92]
/usr/lib/libreoffice/program/libmergedlo.so(_ZN11Application5AbortERKN3rtl8OUStringE+0x98)[0x7f80bea12ed8]
/usr/lib/libreoffice/program/libmergedlo.so(+0x21c6026)[0x7f80bda5f026]
/usr/lib/libreoffice/program/libmergedlo.so(+0x3181ec1)[0x7f80bea1aec1]
/usr/lib/libreoffice/program/libuno_sal.so.3(+0x18832)[0x7f80bb848832]
/usr/lib/libreoffice/program/libuno_sal.so.3(+0x400a7)[0x7f80bb8700a7]
/lib/x86_64-linux-gnu/libc.so.6(+0x43090)[0x7f80bb675090]
/usr/lib/libreoffice/program/libmergedlo.so(_ZNK3vcl6Window9GetCursorEv+0x4)[0x7f80be7473a4]
/usr/lib/libreoffice/program/libmergedlo.so(+0x276cfba)[0x7f80be005fba]
/usr/lib/libreoffice/program/libmergedlo.so(_ZN9Scheduler22CallbackTaskSchedulingEv+0x2fb)[0x7f80bea0372b]
/usr/lib/libreoffice/program/libmergedlo.so(_ZN14SvpSalInstance12CheckTimeoutEb+0x10e)[0x7f80beb835ce]
/usr/lib/libreoffice/program/libmergedlo.so(_ZN14SvpSalInstance7DoYieldEbb+0x8b)[0x7f80beb836db]
/usr/lib/libreoffice/program/libmergedlo.so(+0x3179872)[0x7f80bea12872]
/usr/lib/libreoffice/program/libmergedlo.so(_ZN11Application7ExecuteEv+0x45)[0x7f80bea14d35]
/usr/lib/libreoffice/program/libmergedlo.so(+0x21cdc2b)[0x7f80bda66c2b]
/usr/lib/libreoffice/program/libmergedlo.so(_Z10ImplSVMainv+0x51)[0x7f80bea1c731]
/usr/lib/libreoffice/program/libmergedlo.so(soffice_main+0xa3)[0x7f80bda80523]
/usr/lib/libreoffice/program/soffice.bin(+0x10b0)[0x55edfc86e0b0]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf3)[0x7f80bb656083]
/usr/lib/libreoffice/program/soffice.bin(+0x10ee)[0x55edfc86e0ee]
```

Install the full `libreoffice` package, the `*-nogui` once cause crashes like that, on some files.


# Contributing

Feel free to fork the code, play with it, make some patches and send us the pull requests.

Feel free to contact us, create [issues](https://github.com/pandora-analysis/pandora/issues) if you have questions, remarks or bug reports.

If you have any report concerning security, please read the [SECURITY page](security.md) on how to report security issues and vulnerabilities.

For more details about how to contribute, don't hesitate to have a look at our [contributing](CONTRIBUTING.md) page.

# License

Copyright (C) 2021-2022 [CIRCL](https://www.circl.lu/) - Computer Incident Response Center Luxembourg

Copyright (C) 2021-2022 [Raphaël Vinot](https://github.com/Rafiot) - Computer Incident Response Center Luxembourg

Copyright (C) 2017-2022 [CERT-AG](https://cert-ag.com/) - CERT AG

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
