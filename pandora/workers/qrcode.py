#!/usr/bin/env python3

import cv2

from ..helpers import Status
from ..task import Task
from ..report import Report

from .base import BaseWorker


class QrCodeDecoder(BaseWorker):

    def analyse(self, task: Task, report: Report, manual_trigger: bool=False):
        if not task.file.is_image:
            report.status = Status.NOTAPPLICABLE
            return

        self.logger.debug(f'analysing file {task.file.path}...')
        try:
            image = cv2.imread(str(task.file.path))
            qrCodeDetector = cv2.QRCodeDetector()
            decoded_text, _, _ = qrCodeDetector.detectAndDecode(image)
            if decoded_text:
                report.status = Status.WARN
                report.add_details('qrcode', 'Found a QR Code in the image, go to the observables to see it.')
                if decoded_text.startswith('http'):
                    task.add_observable(decoded_text, 'url')
        except Exception as e:
            self.logger.warning(f'Unable to process image: {e}')
