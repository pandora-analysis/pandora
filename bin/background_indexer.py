#!/usr/bin/env python3

from __future__ import annotations

import logging
import logging.config

from redis import Redis

from pandora import Indexing
from pandora.default import AbstractManager, get_config, get_socket_path


logging.config.dictConfig(get_config('logging'))


class BackgroundIndexer(AbstractManager):

    def __init__(self, loglevel: int | None=None):
        super().__init__(loglevel)
        self.indexing = Indexing()
        self.script_name = 'background_indexer'

        self.redis = Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)

    def _to_run_forever(self) -> None:
        self._check_indexes()

    def _check_indexes(self) -> None:
        if not self.indexing.can_index():
            # There is no reason to run this method in multiple scripts.
            self.logger.info('Indexing already ongoing in another process.')
            return None
        self.logger.info(f'Check {self.script_name}...')
        # NOTE: only get the non-archived captures for now.
        __counter_shutdown = 0
        __counter_shutdown_force = 0
        for uuid, _ in self.indexing.storage.storage.zscan_iter('tasks'):
            __counter_shutdown_force += 1
            if __counter_shutdown_force % 10000 == 0 and self.shutdown_requested():
                self.logger.warning('Shutdown requested, breaking.')
                break

            try:
                if self.indexing.index_task(uuid):
                    __counter_shutdown += 1
            except Exception as e:
                self.logger.warning(f'Error while indexing {uuid}: {e}')
            if __counter_shutdown % 100 == 0 and self.shutdown_requested():
                self.logger.warning('Shutdown requested, breaking.')
                break
        else:
            self.logger.info('... done.')
        self.indexing.indexing_done()


def main() -> None:
    i = BackgroundIndexer()
    i.run(sleep_in_sec=60)


if __name__ == '__main__':
    main()
