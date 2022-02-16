from oletools import olevba  # type: ignore

from ..helpers import Status
from ..task import Task
from ..report import Report

from .base import BaseWorker


class OleVBA(BaseWorker):

    def analyse(self, task: Task, report: Report):
        if not task.file.is_oletools_concerned:
            self.status = Status.NOTAPPLICABLE
            return

        vba_parser = None
        try:
            self.logger.debug(f'analysing file {task.file.path}...')
            vba_parser = olevba.VBA_Parser(task.file.path.name, task.file.data.getvalue())

            # Detect boundsheets
            boundsheets = []
            if vba_parser.detect_vba_macros():
                for macro in vba_parser.reveal().split('\n'):
                    if 'BOUNDSHEET' in macro:
                        boundsheets.append(macro)

            # Detect suspicious elements
            suspicious = []
            observables = []
            analysis = vba_parser.analyze_macros()
            if analysis:
                for type_, keyword, description in analysis:
                    if type_.upper() == 'SUSPICIOUS' and keyword.upper() != 'HEX STRINGS':
                        suspicious.append(description)
                    elif type_.upper() == 'IOC':
                        observables.append(keyword)

            # Set suspicious and boundsheets in report
            if suspicious:
                report.status = Status.ALERT
                report.add_details('suspicious', suspicious)
                if boundsheets:
                    report.add_details('boundsheets', boundsheets)
            elif boundsheets:
                report.status = Status.WARN
                report.add_details('boundsheets', boundsheets)

            # TODO: Add observables in task
            # if observables:
            #    task.set_observables(observables)

        except olevba.FileOpenError:
            # File type is not supported by this module
            pass
        finally:
            if vba_parser is not None:
                vba_parser.close()
