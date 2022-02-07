#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests

from pandora.default import get_homedir, safe_create_dir

jquery_version = "3.6.0"
dropzone_version = "6.0.0-beta.1"
moments_version = "2.29.1"


if __name__ == '__main__':
    dest_dir_js = get_homedir() / 'website' / 'web' / 'static' / 'js' / 'lib'
    safe_create_dir(dest_dir_js)
    dest_dir_css = get_homedir() / 'website' / 'web' / 'static' / 'css' / 'lib'
    safe_create_dir(dest_dir_css)
    dest_dir_font = get_homedir() / 'website' / 'web' / 'static' / 'font' / 'lib'
    safe_create_dir(dest_dir_font)

    jquery = requests.get(f'https://code.jquery.com/jquery-{jquery_version}.min.js')
    with (dest_dir_js / 'jquery.min.js').open('wb') as f:
        f.write(jquery.content)
        print(f'Downloaded jquery v{jquery_version}.')

    moments = requests.get(f'https://cdnjs.cloudflare.com/ajax/libs/moment.js/{moments_version}/moment-with-locales.min.js')
    with (dest_dir_js / 'moment-with-locales.min.js').open('wb') as f:
        f.write(moments.content)
        print(f'Downloaded moments v{moments_version}.')

    dropzone_js = requests.get(f'https://unpkg.com/dropzone@{dropzone_version}/dist/dropzone-min.js')
    with (dest_dir_js / 'dropzone-min.js').open('wb') as f:
        f.write(dropzone_js.content)
        print(f'Downloaded dropzone js v{dropzone_version}')

    dropzone_css = requests.get(f'https://unpkg.com/dropzone@{dropzone_version}/dist/dropzone.css')
    with (dest_dir_css / 'dropzone.css').open('wb') as f:
        f.write(dropzone_css.content)
        print(f'Downloaded dropzone css v{dropzone_version}')

    inconsolata = requests.get('https://github.com/google/fonts/blob/main/ofl/inconsolata/static/Ligconsolata-Regular.ttf?raw=true')
    with (dest_dir_font / 'Ligconsolata-Regular.ttf').open('wb') as f:
        f.write(inconsolata.content)
        print('Downloaded inconsolata')

    print('All 3rd party modules for the website were downloaded.')
