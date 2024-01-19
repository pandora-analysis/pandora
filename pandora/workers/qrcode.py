#!/usr/bin/env python3

from __future__ import annotations

import time

from pathlib import Path
from typing import Generator

import cv2
import numpy as np

from ..helpers import Status
from ..task import Task
from ..report import Report
from ..exceptions import NoPreview

from .base import BaseWorker


class QrCodeDecoder(BaseWorker):

    def _find_boxes(self, image: np.ndarray) -> Generator[tuple[int, int, int, int], None, None]:  # type: ignore[type-arg]
        # code from: https://stackoverflow.com/questions/60359398/python-detect-a-qr-code-from-an-image-and-crop-using-opencv#60384780
        # Load imgae, grayscale, Gaussian blur, Otsu's threshold
        gray = cv2.cvtColor(image.copy(), cv2.COLOR_BGR2GRAY)
        blur = cv2.GaussianBlur(gray, (9, 9), 0)
        thresh = cv2.threshold(blur, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)[1]

        # Morph close
        kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (5, 5))
        close = cv2.morphologyEx(thresh, cv2.MORPH_CLOSE, kernel, iterations=2)

        # Find contours and filter for QR code
        cnts = cv2.findContours(close, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        for c in cnts[0]:
            peri = cv2.arcLength(c, True)
            approx = cv2.approxPolyDP(c, 0.04 * peri, True)

            x, y, w, h = cv2.boundingRect(approx)
            area = cv2.contourArea(c)
            ar = w / float(h)
            if len(approx) == 4 and area > 1000 and (ar > .85 and ar < 1.3):
                # print(x, y, w, h)
                # print(y, y + w, x, x + h)
                yield x, y, w, h

    def _process_image(self, task: Task, report: Report, image_path: Path) -> None:
        self.logger.debug(f'analysing file {image_path}...')
        try:
            image = cv2.imread(str(image_path))
            qrCodeDetector = cv2.QRCodeDetector()
            # foo = qrCodeDetector.detectAndDecode(image[270: 395, 70: 200])
            foo = qrCodeDetector.detectAndDecode(image)
            # print('direct', foo)
            decoded_text, _, _ = foo
            if decoded_text:
                report.status = Status.WARN
                report.add_details('qrcode', 'Found a QR Code in the image, go to the observables to see it.')
                if decoded_text.startswith('http'):
                    task.add_observable(decoded_text, 'url')
                else:
                    task.add_observable(decoded_text, 'text')
            for x, y, w, h in self._find_boxes(image):
                # print('From boxes', y, y + w, x, x + h)
                detect_decode = qrCodeDetector.detectAndDecode(image[y: y + w + 15, x: x + h + 15])
                # print('From boxes', detect_decode)
                if detect_decode[0]:
                    report.status = Status.WARN
                    report.add_details('qrcode', 'Found a QR Code in the image, go to the observables to see it.')
                    if detect_decode[0].startswith('http'):
                        task.add_observable(detect_decode[0], 'url')
                    else:
                        task.add_observable(detect_decode[0], 'text')
        except Exception as e:
            self.logger.warning(f'Unable to process image: {e}')

    def analyse(self, task: Task, report: Report, manual_trigger: bool=False) -> None:
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
