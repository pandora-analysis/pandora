FROM ubuntu:22.04
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV TZ=Etc/UTC

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && \
echo $TZ > /etc/timezone && \
apt-get update && \
apt-get -y upgrade && \
apt-get -y install wget python3-dev git python3-venv python3-pip python-is-python3 \
                   build-essential tcl \
                   libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0 \
                   libreoffice-base-nogui libreoffice-calc-nogui libreoffice-draw-nogui libreoffice-impress-nogui libreoffice-math-nogui libreoffice-writer-nogui \
                   exiftool \
                   unrar \
                   libxml2-dev libxslt1-dev antiword unrtf poppler-utils pstotext tesseract-ocr flac ffmpeg lame libmad0 libsox-fmt-mp3 sox libjpeg-dev swig \
                   libssl-dev \
                   apparmor-utils \
                   libcairo2-dev pkg-config && \
sed '/^profile libreoffice-soffice \/usr\/lib\/libreoffice\/program\/soffice.bin/a owner @{HOME}\/pandora\/tasks\/\*\* rwk,/' /etc/apparmor.d/usr.lib.libreoffice.program.soffice.bin -i && \
pip3 install poetry && \
git clone https://github.com/pandora-analysis/pandora.git && \
cd pandora && \
mkdir tasks && \
echo 'PANDORA_HOME="/pandora"' > .env && \
poetry install --without=dev && \
poetry run tools/3rdparty.py
