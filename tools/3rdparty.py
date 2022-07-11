#!/usr/bin/env python3

import requests

from pandora.default import get_homedir, safe_create_dir

jquery_version = "3.6.0"
dropzone_version = "6.0.0-beta.1"
moments_version = "2.29.4"
datepicker_version = "1.9.0"
chart_version = "3.8.0"

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

    chart = requests.get(f'https://cdnjs.cloudflare.com/ajax/libs/Chart.js/{chart_version}/chart.min.js')
    with (dest_dir_js / 'chart.min.js').open('wb') as f:
        f.write(chart.content)
        print(f'Downloaded chart v{chart_version}.')

    datepicker_js = requests.get(f'https://cdnjs.cloudflare.com/ajax/libs/bootstrap-datepicker/{datepicker_version}/js/bootstrap-datepicker.min.js')
    with (dest_dir_js / 'bootstrap-datepicker.min.js').open('wb') as f:
        f.write(datepicker_js.content)
        print(f'Downloaded datepicker js v{datepicker_version}.')

    datepicker_css = requests.get(f'https://cdnjs.cloudflare.com/ajax/libs/bootstrap-datepicker/{datepicker_version}/css/bootstrap-datepicker.min.css')
    with (dest_dir_css / 'bootstrap-datepicker.min.css').open('wb') as f:
        f.write(datepicker_css.content)
        print(f'Downloaded datepicker css v{datepicker_version}.')

    dropzone_js = requests.get(f'https://unpkg.com/dropzone@{dropzone_version}/dist/dropzone-min.js')
    with (dest_dir_js / 'dropzone-min.js').open('wb') as f:
        f.write(dropzone_js.content)
        print(f'Downloaded dropzone js v{dropzone_version}')

    dropzone_css = requests.get(f'https://unpkg.com/dropzone@{dropzone_version}/dist/dropzone.css')
    with (dest_dir_css / 'dropzone.css').open('wb') as f:
        f.write(dropzone_css.content)
        print(f'Downloaded dropzone css v{dropzone_version}')

    print('All 3rd party modules for the website were downloaded.')
