#!/usr/bin/env python3.8
# -*- coding: utf-8 -*-

"""Aggregator."""

import asyncio
import logging
import time
from datetime import datetime, timedelta
from os import abort
from typing import Any, Dict, List, Union

from pymisp import mispevent
from tno.mpc.encryption_schemes.shamir import ShamirShares

from sacti.config import (
    ABORT_MSG,
    AGGREGATOR_ID,
    AGGREGATOR_PORT,
    DAYS,
    HARDCODED_MISP_LAST_EVENTS,
    MISP,
    MISP_KEY,
    MISP_URL,
    PARTIES,
    PARTIES_CONFIG,
    PARTIES_LIST,
)
from sacti.message import CheckShares, PrometheusEventMessage, SightingShare
from sacti.prometheus import Prometheus, ProtocolStage
from sacti.utils import log

httphandlers = logging.getLogger("tno.mpc.communication.httphandlers")
httphandlers.setLevel(logging.ERROR)


class Aggregator(Prometheus):
    """Aggregator class for the Prometheus MPC protocol for secure IOC data sharing."""

    _messages: Dict[Any, Any] = {}
    id: int = AGGREGATOR_ID

    def __init__(
        self, misp_url: str, misp_key: str, port: int = AGGREGATOR_PORT
    ) -> None:
        """Initialize a new aggregator."""
        log.info("Init aggregator...")

        super().__init__(misp_url, misp_key, port)
        self.__init_pool()
        self._init_pki()

    def __init_pool(self) -> None:
        """Initialize a new pool."""
        for host in PARTIES_CONFIG:
            self.pool.add_http_client(host[0], host[1], host[2])

    ###################### ROUTING ########################
    async def route_msg(self) -> None:
        """Route messages between the parties in the protocol."""
        log.info("Routing messages among parties...")
        self.protocol_stage: Any

        while self.protocol_stage != ProtocolStage.COMPUTE_AGGREGATION:
            await self.receive_from_all(routing=True)
            for sender, data in self._messages.items():
                for receiver in data.keys():
                    log.debug(
                        f"Sending shares with id {str(self.protocol_stage)} {sender} -> {receiver} "
                    )
                    enc_data = {sender: data[receiver]}
                    await self.pool.send(
                        str(receiver), enc_data, str(self.protocol_stage)
                    )
            self.protocol_stage = self.protocol_stage.next()

    async def receive_from_all(self, routing: bool = False) -> None:
        """Wait for messages from all parties in the protocol."""
        aborted = set()
        self._messages = {}
        log.debug(f"Waiting for messages with {str(self.protocol_stage)}")

        for party in PARTIES_LIST:
            self._messages[party] = await self.pool.recv(
                str(party), str(self.protocol_stage)
            )
            if self._messages[party] == ABORT_MSG:
                aborted.add(party)

        if len(aborted):
            log.error(f"Aborting protocol: {ABORT_MSG} received...")
            for party in PARTIES_LIST:
                if party not in aborted:
                    await self.pool.send(
                        str(party), ABORT_MSG, str(self.protocol_stage)
                    )
            raise SystemExit()

        if not routing:
            for party in PARTIES_LIST:
                self._messages[party] = self.decrypt_and_check_msg(
                    self._messages[party], party
                )

            log.debug(f"Received msg from {party}")

    async def broadcast(self, data: Any) -> None:
        """Send data to every party in the protocol through the aggregator."""
        for pid in PARTIES_LIST:
            await self.pool.send(
                str(pid),
                self.encrypt_and_sign_msg(data, pid),
                self.protocol_stage,
            )
        self.protocol_stage = self.protocol_stage.next()

    ######################################################

    ######################## MISP ########################

    def _get_last_events(self, days: int = DAYS) -> Any:
        """Get the last event from MISP."""
        if MISP:
            starting_date = datetime.now() - timedelta(days=days)
            res = [
                r["uuid"]
                for r in self.misp.search_index(
                    date_from=starting_date.strftime("%Y-%m-%d")
                )
            ]
            log.debug(f"Fetched from MISP: {res}")
            if res == []:
                raise Exception("No events in the defined time range.")
            return res

        return HARDCODED_MISP_LAST_EVENTS

    def __add_sighting(self, attribute_id: str) -> None:
        """
        Add one sighting to a MISP attribute.

        :param attribute_id: Attribute ID/UUID to be updated.
        """
        sighting = mispevent.MISPSighting()  # type:ignore
        sighting.from_dict(timestamp=time.time())  # type:ignore
        self.misp.add_sighting(attribute=attribute_id, sighting=sighting)

    def update_attribute_sightings(self, attribute_id: str, amount: int) -> None:
        """
        Update the number of sightings of a MISP attribute.

        :param attribute_id: Attribute ID/UUID to be updated.
        :param amount: Sightings increase.
        """
        for _ in range(amount):
            self.__add_sighting(attribute_id)

    def update_event_damage(self, event_id: str, damage: int) -> None:
        """
        Update a MISP event with a prometheus-financial-damage object.

        :param event_id: Event ID/UUID to be updated.
        :param damage: Aggregated financial damage for the event.
        """
        new_obj = mispevent.MISPObject(
            "prometheus-financial-damage",
            standalone=False,
            misp_objects_path_custom=".",
        )
        new_obj.add_attribute(object_relation="damage", simple_value=damage)
        event = self.misp.get_event(event=event_id, pythonify=True)
        event.add_object(new_obj)
        self.misp.update_event(event, event_id=event_id)

    def update_misp_events(self, events_dict: Dict[Any, Any]) -> None:
        """Update the MISP instance events with the computed aggregated values."""
        log.info("Updating MISP...")

        for event_uuid, event_data in events_dict.items():
            for attribute, amount in event_data["sightings"].items():
                if amount != 0:
                    self.update_attribute_sightings(
                        attribute_id=attribute, amount=amount
                    )
            if event_data["damage"] != 0:
                self.update_event_damage(event_uuid, event_data["damage"])

    ######################################################

    async def send_ioc(self, days: int) -> None:
        """
        Send the events list to every party in the protocol.

        :param days: Number of precedent days to retrieve events from.
        """
        await self.broadcast(self._get_last_events(days))

    async def collect_shares(self) -> Dict[str, PrometheusEventMessage]:
        """Prepare the shares for the reconstruction phase."""
        log.info("Waiting for partial sums...")
        await self.receive_from_all()
        shares: Dict[str, PrometheusEventMessage] = {}
        for event_uuid, event_data in self._messages[PARTIES_LIST[0]]["events"].items():
            # Some debatable variable declarations, but they make mypy happy
            sightings = {}  # type: Dict[str, Union[Dict[Any,Any], CheckShares, int]]
            damage = {}  # type: Dict[int, Any]
            shares[event_uuid] = PrometheusEventMessage(
                uuid=event_uuid, sightings=sightings, damage=damage
            )
            for attribute_uuid in event_data.sightings.keys():
                emptyDict = {}  # type: Dict[str, Any]
                shares[event_uuid].sightings.update({attribute_uuid: emptyDict})
                for party in PARTIES_LIST:
                    assert isinstance(
                        shares[event_uuid].sightings[attribute_uuid], dict
                    ), "Incompatible type"
                    shares[event_uuid].sightings[attribute_uuid].update(  # type:ignore
                        {
                            party: self._messages[party]["events"][
                                event_uuid
                            ].sightings[attribute_uuid]
                        }
                    )
            for party in PARTIES_LIST:
                assert isinstance(shares[event_uuid].damage, dict), "Wrong damage type"
                shares[event_uuid].damage.update(  # type:ignore
                    {party: self._messages[party]["events"][event_uuid].damage}
                )

        return shares

    def compute_result(
        self, res: Dict[Any, Any]
    ) -> Dict[str, Dict[str, Union[Dict[str, int], int]]]:
        """Compute the result by combining the received shares."""
        log.info("Computing result...")
        events_final: Dict[str, Dict[str, Union[Dict[str, int], int]]] = {}
        for event_uuid, event_data in res.items():
            events_final[event_uuid] = {"sightings": {}, "damage": {}}
            for attribute_uuid, shares in event_data.sightings.items():
                events_final[event_uuid]["sightings"] = {
                    attribute_uuid: ShamirShares(self.ssss, shares).reconstruct_secret()
                }
            events_final[event_uuid]["damage"] = ShamirShares(
                self.ssss, event_data.damage
            ).reconstruct_secret()

        return events_final

    async def prometheus_protocol(self, days: int = DAYS) -> None:
        """
        Start the MPC protocol for secure IOC data sharing, considering MISP events from the last days.

        :param days: Number of precedent days.
        """
        await self.send_ioc(days)
        await self.route_msg()

        shares = await self.collect_shares()

        sightings_final = self.compute_result(shares)
        log.debug(f"{sightings_final=}")

        if MISP:
            self.update_misp_events(sightings_final)


async def async_main() -> None:
    """Start main async loop."""
    aggregator = Aggregator(MISP_URL, MISP_KEY)

    await aggregator.prometheus_protocol()

    log.info("DONE!")


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(async_main())
