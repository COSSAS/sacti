#!/usr/bin/env python3.8
# -*- coding: utf-8 -*-

"""Party."""

import asyncio
import logging
import sys
from copy import deepcopy
from hashlib import sha256
from secrets import randbelow
from typing import Any, Dict, List, Optional, Union

from tno.mpc.encryption_schemes.shamir import ShamirSecretSharingScheme, ShamirShares

from sacti.config import (
    ABORT_MSG,
    AGGREGATOR_ID,
    EVENTS_NUMBER,
    HARDCODED_ATTRIBUTE_IDS,
    MAX_ZEROS,
    MISP,
    MISP_KEY,
    MISP_URL,
    MODULUS,
    PARTIES,
    PARTIES_LIST,
    PKI,
    POLYNOMIAL_DEGREE,
    RANDOM_RANGE,
)
from sacti.message import CheckShares, PrometheusEvent, PrometheusEventMessage
from sacti.prometheus import Prometheus, ProtocolStage
from sacti.utils import bitlist_to_int, log

httphandlers = logging.getLogger("tno.mpc.communication.httphandlers")
httphandlers.setLevel(logging.CRITICAL)


class Party(Prometheus):
    """Party class for the Prometheus MPC protocol for secure IOC data sharing."""

    own_shares: Dict[str, Union[int, Dict[int, PrometheusEventMessage], List[int]]] = {}
    events_list: Optional[List[Any]] = None
    random_weights: Optional[List[Any]] = None
    shares_from_others: Optional[List[Any]] = None

    def __init__(
        self,
        ID: int,
        aggregator_address: str,
        aggregator_port: int,
        port: int,
        misp_url: str,
        misp_key: str,
    ) -> None:
        """Initialize a new party."""
        log.info(f"Init party {id}...")

        super().__init__(misp_url, misp_key, port)
        self.id = ID
        self.random_seed: Union[int, ShamirShares] = self.ssss.share_secret(
            randbelow(RANDOM_RANGE)
        )
        # Slicing the list create a new list instead of a reference to the global one
        self.other_parties = PARTIES_LIST[:]
        self.other_parties.remove(self.id)
        self._init_pool(aggregator_address, aggregator_port)
        self._init_pki()
        self.temp_ss = ShamirShares(self.ssss, {self.id: 1})
        temp_scheme = ShamirSecretSharingScheme(
            modulus=MODULUS,
            number_of_parties=PARTIES,
            polynomial_degree=2 * POLYNOMIAL_DEGREE,
        )

        self.zero: Union[List[int], List[ShamirShares]] = [
            temp_scheme.share_secret(0) for _ in range(3)
        ]

    def _init_pool(self, aggregator_address: str, aggregator_port: int) -> None:
        """Initialize a new pool."""
        self.pool.add_http_client(
            "Aggregator", aggregator_address, port=aggregator_port
        )

    async def send(self, message: Any) -> None:
        """
        Send an encrypted and signed message to other parties through the aggregator.

        :param message: It is a dictionary where the outer keys indicate the receivers.
        """
        self.protocol_stage: Any = self.protocol_stage.next()
        msg_id = str(self.protocol_stage)
        if PKI and message != ABORT_MSG:
            for receiver in message.keys():
                message[receiver] = self.encrypt_and_sign_msg(
                    message[receiver],
                    receiver,
                )
                log.debug(f"Sending shares to {receiver} with id {msg_id}")
        await self.pool.send("Aggregator", message, msg_id)

    async def receive_all(self) -> Dict[Any, Any]:
        """Receive messages from every party in the protocol through the aggregator."""
        log.debug(f"Waiting for messages with {str(self.protocol_stage)}")

        res = {}
        for _ in self.other_parties:

            msg = await self.pool.recv("Aggregator", str(self.protocol_stage))
            if msg == ABORT_MSG:
                log.error(f"Aborting protocol: {ABORT_MSG} received...")
                raise SystemExit()
            sender, data = list(msg.items())[0]
            if PKI:
                res[sender] = self.decrypt_and_check_msg(data, sender)
            else:
                res[sender] = data
        return res

    async def receive_events(self) -> None:
        """Receive initial event list from the aggregator."""
        self.events_list = await self.pool.recv("Aggregator", self.protocol_stage)
        if PKI:
            assert isinstance(
                self.events_list, bytes
            ), "Events list is supposed to be a bytes object"
            self.events_list = self.decrypt_and_check_msg(
                self.events_list,
                AGGREGATOR_ID,
            )

    async def broadcast(self, msg: Union[int, Dict[str, Any]]) -> None:
        """Broadcast message to parties."""
        data = {}
        for party in self.other_parties:
            data[party] = msg

        await self.send(data)

    ######################################################

    ###################### CHECKS ########################
    def _x_sub_x2(self, bit_share: ShamirShares) -> ShamirShares:
        """Share bits."""
        bs = deepcopy(bit_share)
        square = bs * bs
        bs.scheme.polynomial_degree = square.scheme.polynomial_degree

        return bs - square

    def _compute_check_bit_shares(self, bitlists: List[Any]) -> int:
        """Compute and check bit shares."""
        res = 0
        for l in bitlists:
            for b in l:
                self.temp_ss.shares = {1: b}
                w = self._new_random_weight()
                t = self._x_sub_x2(self.temp_ss).shares[1]
                res += (t * w) % MODULUS
        return res

    def _compute_check_belongs_shares(self, bitlists: List[Any]) -> int:
        """Compute and check belong shares."""
        res = 0
        for l in range(1, len(bitlists)):
            temp_check = sum(bitlists[l - 1]) % MODULUS
            temp_check -= bitlist_to_int(bitlists[l], MODULUS)
            temp_check = (temp_check * self._new_random_weight()) % MODULUS
            res += temp_check
        return res

    def _compute_check_non_zero(self, bitlist: List[Any]) -> Any:
        """Compute and check for non zero."""
        # bitlist has always length 2 by design
        self.temp_ss.shares = {self.id: bitlist[0]}
        temp = deepcopy(self.temp_ss)
        temp.shares = {self.id: bitlist[1]}
        return (self.temp_ss * temp).shares[self.id]

    async def check_inputs(self, res: Dict[Any, Any]) -> None:
        """Check that input shares actually represent bits."""
        await self.compute_shared_random_and_zero(res)
        log.info("Checking inputs...")

        check = 0
        res[self.id] = self.own_shares
        # compute x_{i,j}(1-x_{i,j})
        for party in PARTIES_LIST:
            for _, event in res[party]["events"].items():
                for _, css in event.sightings.items():
                    # 3.3.4/5: check if bits belong to share
                    check += self._compute_check_belongs_shares(css.is_bit)
                    # 3.3.3 : check if bits shares x_{i,j} are really bits
                    check += self._compute_check_bit_shares(css.is_bit)

                # 3.3.4/5: check if bits belong to share
                check += self._compute_check_belongs_shares(event.damage.is_bit)
                # 3.3.3 : check if bits shares x_{i,j} are really bits
                check += self._compute_check_bit_shares(event.damage.is_bit)

                assert isinstance(self.zero[0], int)
                check += self.zero[0]

        # check shares are from bits
        await self.broadcast(check)
        shares = await self.receive_all()
        # to retrieve the proper share schema(degree), value (shares parameter) will be overwritten
        temp_ss = self._x_sub_x2(self.temp_ss)
        shares[self.id] = check
        temp_ss.shares = shares
        if temp_ss.reconstruct_secret() != 0:
            await self.send(ABORT_MSG)
            log.error("Aborting protocol due to malformed input...")
            raise SystemExit()

    async def count_zero_inputs(self, res: Dict[Any, Any]) -> None:
        """Count the num."""
        log.info("Counting zero-valued inputs ...")

        # 3.3.5: if number of nonzero is ok, then send to server, otherwise set to zero

        check_shares = deepcopy(res)
        check_shares[self.id] = deepcopy(self.own_shares)

        count: Dict[str, Dict[str, Union[int, List[int]]]] = {}
        assert self.events_list is not None, "Event list is empty"
        for event_uuid in self.events_list:
            count[event_uuid] = {}
            for attribute_uuid in check_shares[self.id]["events"][
                event_uuid
            ].sightings.keys():
                count[event_uuid][attribute_uuid] = []
                for party in PARTIES_LIST:
                    two_bit_list = (
                        check_shares[party]["events"][event_uuid]
                        .sightings[attribute_uuid]
                        .is_bit[-1]
                    )
                    two_bit_list = [((1 - z)) % MODULUS for z in two_bit_list]
                    assert isinstance(
                        count[event_uuid][attribute_uuid], list
                    ), "Count element is not a list"
                    count[event_uuid][attribute_uuid].append(  # type:ignore
                        (two_bit_list[0] * two_bit_list[1]) % MODULUS
                    )
                assert isinstance(
                    self.zero[1], int
                ), "Incorrect type of own shares zero"
                assert isinstance(
                    count[event_uuid][attribute_uuid], list
                ), "Count element is not a list"
                count[event_uuid][attribute_uuid] = (
                    sum(count[event_uuid][attribute_uuid]) + self.zero[1]  # type:ignore
                ) % MODULUS
            count[event_uuid]["damage"] = []
            for party in PARTIES_LIST:
                two_bit_list = check_shares[party]["events"][event_uuid].damage.is_bit[
                    -1
                ]
                two_bit_list = [((1 - x)) % MODULUS for x in two_bit_list]
                assert isinstance(
                    count[event_uuid]["damage"], list
                ), "Count element is not a list"
                count[event_uuid]["damage"].append(  # type:ignore
                    (two_bit_list[0] * two_bit_list[1]) % MODULUS
                )
            assert isinstance(self.zero[2], int), "Wrong type of own shares zero"
            assert isinstance(
                count[event_uuid]["damage"], list
            ), "Count element is not a list"
            count[event_uuid]["damage"] = (
                sum(count[event_uuid]["damage"]) + self.zero[2]  # type:ignore
            ) % MODULUS

        # check shares are from bits
        await self.broadcast(count)
        res = await self.receive_all()
        res[self.id] = count
        number_of_zero_inputs = self.temp_ss * self.temp_ss  # get proper degree

        for event_uuid in self.events_list:
            for attribute_uuid in count[event_uuid].keys():
                number_of_zero_inputs.shares = {
                    p: res[p][event_uuid][attribute_uuid] for p in PARTIES_LIST
                }

                if number_of_zero_inputs.reconstruct_secret() > MAX_ZEROS:
                    assert isinstance(
                        self.own_shares["events"], list
                    ), "Wrong type of own shares events"
                    if attribute_uuid == "damage":
                        self.own_shares["events"][event_uuid].damage = 0
                    else:
                        self.own_shares["events"][event_uuid].sightings[
                            attribute_uuid
                        ] = 0

        log.debug("Number of zero inputs per attribute:")
        log.debug(f"{self.own_shares=}")

    ######################################################

    async def send_inputs(self, data: Dict[Any, Any]) -> None:
        """Send inputs through the aggregator."""
        log.info("Sending shares through Aggregator...")

        assert all(
            [isinstance(z, ShamirShares) for z in self.zero]
        ), "Incorrect type of zero shares"
        assert isinstance(
            self.random_seed, ShamirShares
        ), "Incorrect type of random zero shares"
        msg: Dict[
            int, Dict[str, Union[int, Dict[int, PrometheusEventMessage], List[int]]]
        ] = {
            p: {
                "events": {},
                "zero": [z.shares[p] for z in self.zero],  # type:ignore
                "random": self.random_seed.shares[p],
            }
            for p in PARTIES_LIST
        }

        # 3.3.1 transfrom sightings to bin and shares bits
        for event_uuid in data.keys():

            event = PrometheusEvent(
                event_uuid,
                data[event_uuid]["sightings"],
                data[event_uuid]["damage"],
                self.ssss,
            )
            for party, prom_event_msg in event.generate_msg().items():
                assert isinstance(msg[party]["events"], dict), "Incorrect event type"
                msg[party]["events"].update(prom_event_msg)  # type:ignore

        self.own_shares = deepcopy(msg[self.id])
        del msg[self.id]
        await self.send(msg)

    def _compute_shares_from_bits(self, res: Dict[Any, Any]) -> Any:
        """Compute shares from bits."""
        log.info(f"Locally computing shares of the inputs from bits")

        # 3.3.2 : recompute shares x_i from bits
        d = deepcopy(self.own_shares)
        assert self.events_list is not None, "Empty event list"
        for event_uuid in self.events_list:
            assert isinstance(
                self.own_shares["events"], dict
            ), "Incorrect type of events within own shares"
            for attribute_uuid, css in self.own_shares["events"][
                event_uuid
            ].sightings.items():
                assert isinstance(
                    d["events"], dict
                ), "Wrong type of event field of own shares"
                if css == 0:
                    d["events"][event_uuid].sightings[attribute_uuid] = 0
                else:
                    assert isinstance(
                        css, CheckShares
                    ), "Incorrect type of check shares"
                    for i, l in enumerate(css.is_bit):
                        for j, b in enumerate(l):
                            # Sum bit shares
                            temp = b
                            for p in self.other_parties:
                                temp = (
                                    temp
                                    + res[p]["events"][event_uuid]
                                    .sightings[attribute_uuid]
                                    .is_bit[i][j]
                                ) % MODULUS
                                assert isinstance(
                                    d["events"][event_uuid].sightings[attribute_uuid],
                                    CheckShares,
                                ), "Incorrect type of sighting"
                                d["events"][event_uuid].sightings[  # type:ignore
                                    attribute_uuid
                                ].is_bit[i][j] = temp

                    # Compute share from bits
                    assert isinstance(
                        d["events"][event_uuid].sightings[attribute_uuid], CheckShares
                    ), "Incorrect type of sighting"
                    d["events"][event_uuid].sightings[attribute_uuid] = bitlist_to_int(
                        d["events"][event_uuid]  # type:ignore
                        .sightings[attribute_uuid]
                        .is_bit[0],
                        MODULUS,
                    )

            # event damage
            event = self.own_shares["events"][event_uuid]
            assert isinstance(d["events"], dict), "Wrong type of own shares for event"
            if event.damage == 0:
                print("CHECK THIS OUT")
                d["events"][event_uuid].damage = 0
            else:
                assert isinstance(
                    event.damage, CheckShares
                ), "Wrong type of event damage"
                for i, l in enumerate(event.damage.is_bit):
                    for j, b in enumerate(l):
                        # Sum bit shares
                        temp = b
                        for p in self.other_parties:
                            temp = (
                                temp + res[p]["events"][event_uuid].damage.is_bit[i][j]
                            ) % MODULUS
                            assert isinstance(
                                d["events"][event_uuid].damage, CheckShares
                            ), "Wrong type of event damage"
                            d["events"][event_uuid].damage.is_bit[i][  # type:ignore
                                j
                            ] = temp

                # Compute share from bits
                assert isinstance(
                    d["events"][event_uuid].damage, CheckShares
                ), "Wrong type of event damage"
                d["events"][event_uuid].damage = bitlist_to_int(
                    d["events"][event_uuid].damage.is_bit[0], MODULUS  # type:ignore
                )

        return d

    def _new_random_weight(self) -> Any:
        """Create new random weights."""
        if not self.random_weights:
            self.random_weights = [
                1
                + (
                    int.from_bytes(
                        sha256(str(self.random_seed).encode()).digest(), "big"
                    )
                    % (MODULUS - 1)
                )
            ]
        else:
            new_random_weight = int.from_bytes(
                sha256(str(self.random_weights[-1]).encode()).digest(), "big"
            )
            self.random_weights.append(1 + (new_random_weight % (MODULUS - 1)))
        return self.random_weights[-1]

    async def compute_shared_random_and_zero(self, res: Dict[Any, Any]) -> None:
        """Compute shared random seed."""
        log.info("Computing shared random seed...")

        random = self.own_shares["random"]
        assert isinstance(self.own_shares["zero"], list), "Wrong type of zero shares"
        self.zero = [z for z in self.own_shares["zero"]]
        for party in self.other_parties:
            random = (random + res[party]["random"]) % MODULUS
            for i, _ in enumerate(self.zero):
                self.zero[i] += res[party]["zero"][i]
        assert isinstance(
            self.random_seed, ShamirShares
        ), "Random seed has incorrect type"
        self.random_seed.shares = {self.id: random}  # type:ignore

        await self.broadcast({"random": random})
        random_res = await self.receive_all()
        self.random_seed.shares.update(
            {p: random_res[p]["random"] for p in self.other_parties}
        )
        self.random_seed = self.random_seed.reconstruct_secret()

    def reconstruct(self, shares: Dict[int, int]) -> Any:
        """Reconstruct ShamirShares."""
        return ShamirShares(self.ssss, shares).reconstruct_secret()

    async def compute_and_send_partials(self, res: Dict[Any, Any]) -> None:
        """Compute and send partials."""
        log.info("Computing and send partial sum...")

        partials = self._compute_shares_from_bits(res)
        partials = self.encrypt_and_sign_msg(partials, AGGREGATOR_ID)
        self.protocol_stage = self.protocol_stage.next()
        log.debug(f"Sending shares to Aggregator with id {str(self.protocol_stage)}")
        if PKI:
            await self.pool.send("Aggregator", partials, str(self.protocol_stage))

    async def prometheus_protocol(
        self, input_data: Optional[Dict[Any, Any]] = None
    ) -> None:
        """Start the Prometheus protocol."""
        await self.receive_events()

        assert self.events_list is not None, "Empty event list"
        self.events_list = self.events_list[:EVENTS_NUMBER]

        if not input_data:
            input_data = generate_random_input(self)

        await self.send_inputs(input_data)
        res = await self.receive_all()

        await self.check_inputs(res)
        # this can be also done in parallel with check inputs to reduce the communications round
        await self.count_zero_inputs(res)
        await self.compute_and_send_partials(res)


async def async_main() -> None:
    """Start the main async party loop."""
    party = Party(
        ID=int(sys.argv[1]),
        aggregator_address="127.0.0.1",
        aggregator_port=9181,
        port=int(sys.argv[2]),
        misp_url=MISP_URL,
        misp_key=MISP_KEY,
    )

    # It is possible to directly pass th input data here
    await party.prometheus_protocol()

    log.info("DONE!")


def generate_random_input(party: Party) -> Dict[Any, Any]:
    """Generate some random-valued input for the party."""
    assert party.events_list is not None, "Empty event list"
    if MISP:
        input_data: Dict[Any, Any] = {}
        events = [
            party.misp.get_event(event=e, pythonify=True) for e in party.events_list
        ]
        for event in events:
            input_data[event.uuid] = {"sightings": {}}
            for attribute in event["Attribute"]:
                input_data[event.uuid]["sightings"][attribute.uuid] = randbelow(
                    RANDOM_RANGE
                )
            input_data[event.uuid]["damage"] = randbelow(RANDOM_RANGE)
    else:
        input_data = {e: {"sightings": {}} for e in party.events_list}
        for attribute in HARDCODED_ATTRIBUTE_IDS:
            for event in party.events_list:
                input_data[event]["sightings"][attribute] = randbelow(RANDOM_RANGE)
                input_data[event]["damage"] = randbelow(RANDOM_RANGE)
    log.info(f"INPUT DATA: {input_data}")
    return input_data


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(async_main())
