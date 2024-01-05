#!/usr/bin/env python3

import time

from pathlib import Path

import cv2

from ..helpers import Status
from ..task import Task
from ..report import Report
from ..exceptions import NoPreview

from .base import BaseWorker


class QrCodeDecoder(BaseWorker):

    def _process_image(self, task: Task, report: Report, image_path: Path):
        self.logger.debug(f'analysing file {image_path}...')
        try:
            image = cv2.imread(str(image_path))
            qrCodeDetector = cv2.QRCodeDetector()
            decoded_text, _, _ = qrCodeDetector.detectAndDecode(image)
            if decoded_text:
                report.status = Status.WARN
                report.add_details('qrcode', 'Found a QR Code in the image, go to the observables to see it.')
                if decoded_text.startswith('http'):
                    task.add_observable(decoded_text, 'url')
                else:
                    task.add_observable(decoded_text, 'text')

        except Exception as e:
            self.logger.warning(f'Unable to process image: {e}')

    def analyse(self, task: Task, report: Report, manual_trigger: bool=False):
        if task.file.is_image:
            self._process_image(task, report, task.file.path)
        else:
            # Attempt to run module on previews
            try:
                task.file.paths_to_preview()
            except NoPreview:
                report.status = Status.NOTAPPLICABLE
                return

            time.sleep(5)
            # It can take a while to generate the previews, so we wait for them a little bit
            for _ in range(5):
                if task.file.previews:
                    break
                time.sleep(2)
            else:
                report.status = Status.NOTAPPLICABLE
                return

            for preview in task.file.previews:
                self._process_image(task, report, preview)
