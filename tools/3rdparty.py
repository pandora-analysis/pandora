#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests

from pandora.default import get_homedir, safe_create_dir

jquery_version = "3.6.0"
dropzone_version = "6.0.0-beta.1"


if __name__ == '__main__':
    dest_dir_js = get_homedir() / 'website' / 'web' / 'static' / 'js' / 'lib'
    dest_dir_css = get_homedir() / 'website' / 'web' / 'static' / 'css' / 'lib'
    safe_create_dir(dest_dir_js)
    safe_create_dir(dest_dir_css)

    jquery = requests.get(f'https://code.jquery.com/jquery-{jquery_version}.min.js')
    with (dest_dir_js / 'jquery.min.js').open('wb') as f:
        f.write(jquery.content)
        print(f'Downloaded jquery v{jquery_version}.')

    dropzone_js = requests.get(f'https://unpkg.com/dropzone@{dropzone_version}/dist/dropzone-min.js')
    with (dest_dir_js / 'dropzone-min.js').open('wb') as f:
        f.write(dropzone_js.content)
        print(f'Downloaded dropzone js v{dropzone_version}')

    dropzone_css = requests.get(f'https://unpkg.com/dropzone@{dropzone_version}/dist/dropzone.css')
    with (dest_dir_css / 'dropzone.css').open('wb') as f:
        f.write(dropzone_css.content)
        print(f'Downloaded dropzone css v{dropzone_version}')

    print('All 3rd party modules for the website were downloaded.')
