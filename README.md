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
