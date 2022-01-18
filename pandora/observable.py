from datetime import datetime
import urllib.parse

import validators  # type: ignore

from typing import List, Optional, Union

from .helpers import TypeObservable, make_bool_for_redis, make_bool
from .storage_client import Storage


class Observable:

    def __init__(self, link: Optional[str]=None, allowlist: Union[str, bool, int]=False,
                 address: Optional[str]=None,
                 type_observable: Optional[Union[str, TypeObservable]]=None,
                 save_date: Optional[Union[str, datetime]]=None):
        """
        Generate observable from link.
        :param type_: observable type
        :param link: string to parse
        :param id_: observable id from mysql
        :param address: domain name or IP address
        :param save_date: save date
        :param allowlist: boolean
        """

        self.storage = Storage()

        # FIXME this is dirty
        if link is None:
            self.link = address
        else:
            self.link = link

        self.allowlist = make_bool(allowlist)

        self.type_observable: TypeObservable
        if type_observable is not None:
            if isinstance(type_observable, str):
                self.type_observable = TypeObservable[type_observable]
            else:
                self.type_observable = type_observable

        self.address: str
        if address is not None:
            self.address = address

        if not save_date:
            self.save_date = datetime.now()
        elif isinstance(save_date, str):
            self.save_date = datetime.fromisoformat(save_date)
        else:
            self.save_date = save_date
        self._parse_link()

    @property
    def to_dict(self):
        return {
            'type_observable': self.type_observable.name,
            'link': self.link,
            'address': self.address,
            'save_date': self.save_date.isoformat(),
            'allowlist': make_bool_for_redis(self.allowlist)
        }

    @property
    def store(self):
        self.storage.set_observable(self.to_dict)

    def _parse_link(self):
        """
        Parse link to check if it is a URL, domain name or ip address.
        """
        if validators.url(self.link) is True:
            parsed = urllib.parse.urlparse(self.link)
            if parsed and parsed.hostname:
                if isinstance(parsed.hostname, bytes):
                    address: str = parsed.hostname.decode()
                else:
                    address = parsed.hostname
        elif self.link:
            address = self.link

        try:
            if validators.domain(address):
                self.address = address
                self.type_observable = TypeObservable.DOMAIN
            elif validators.ip_address.ipv4(address):
                self.address = address
                self.type_observable = TypeObservable.IPV4
            elif validators.ip_address.ipv6(address):
                self.address = address
                self.type_observable = TypeObservable.IPV6
            elif validators.email(address):
                self.address = address
                self.type_observable = TypeObservable.EMAIL
            elif validators.iban(address):
                self.address = address
                self.type_observable = TypeObservable.IBAN
            # case validators.url is too restrictive (full RFC compliant)
            # elif urllib.parse.urlparse(address).netloc is not None:
            #     self.address = urllib.parse.urlparse(address).netloc
            #     self.type_observable = TypeObservable.DOMAIN
        except ValueError:
            pass


class TaskObservable:

    @staticmethod
    def get_observables(links, allowlist=False) -> List[Observable]:
        """
        Generate list of Observable objects from links.
        and update first address with all links reference pointing on it.
        :param (list) links: list of links
        :param (bool) allowlist: whether to mark observables in allowlist
        :return (list): list of unique observables
        """
        observables: List[Observable] = []
        for link in links:
            observable = Observable(link=link, allowlist=allowlist)
            if observable.address is not None:
                for o in observables:
                    if observable.address == o.address and observable.link != o.link and observable.link and o.link:
                        o.link += "\n\r" + observable.link
                observables.append(observable)
        return observables
