"""Недоверенный relay: хранит prekey-bundle и пересылает непрозрачные конверты. Расшифровать он не может."""
import base64
import json
from dataclasses import dataclass

from e2ee import (IdentityKeyPair, IdentityPublic, IdentityChanged, InitialHeader, PrekeyBundle, PrekeyStore,
                  Ratchet, E2EEError, DecryptionError, x3dh_initiate, x3dh_respond)

b64 = lambda b: base64.b64encode(b).decode()
unb64 = lambda s: base64.b64decode(s.encode(), validate=True)


class Relay:
    def __init__(self):
        self._bundles: dict[str, dict] = {}
        self._queues: dict[str, list[bytes]] = {}
        self.seen: list[bytes] = []          # всё, что видел relay (для проверок в тестах)

    def publish(self, user: str, identity: IdentityPublic, spk_id: int, spk: bytes, spk_sig: bytes, opks):
        self._bundles[user] = dict(identity=identity, spk_id=spk_id, spk=spk, spk_sig=spk_sig, opks=list(opks))

    def fetch_bundle(self, user: str) -> PrekeyBundle:
        b = self._bundles.get(user)
        if b is None:
            raise E2EEError(f"{user}: нет опубликованных ключей")
        opk_id, opk = b["opks"].pop(0) if b["opks"] else (None, None)     # одноразовый prekey выдаётся один раз
        return PrekeyBundle(b["identity"], b["spk_id"], b["spk"], b["spk_sig"], opk_id, opk)

    def post(self, to: str, envelope: bytes):
        self.seen.append(envelope)
        self._queues.setdefault(to, []).append(envelope)

    def poll(self, user: str) -> list[bytes]:
        q, self._queues[user] = self._queues.get(user, []), []
        return q


def encode_envelope(sender: str, init: InitialHeader | None, header: bytes, ct: bytes) -> bytes:
    d = {"from": sender, "header": b64(header), "ct": b64(ct), "init": None}
    if init:
        d["init"] = {"ik_dh": b64(init.identity.dh), "ik_sig": b64(init.identity.sig), "ek": b64(init.ek),
                     "spk_id": init.spk_id, "opk_id": init.opk_id}
    return json.dumps(d, sort_keys=True).encode()


def decode_envelope(raw: bytes):
    try:
        d = json.loads(raw)
        init = None
        if d["init"]:
            i = d["init"]
            init = InitialHeader(IdentityPublic(unb64(i["ik_dh"]), unb64(i["ik_sig"])), unb64(i["ek"]),
                                 int(i["spk_id"]), None if i["opk_id"] is None else int(i["opk_id"]))
        return d["from"], init, unb64(d["header"]), unb64(d["ct"])
    except (KeyError, ValueError, TypeError, json.JSONDecodeError) as e:
        raise DecryptionError(f"битый конверт: {e}")


class Client:
    def __init__(self, name: str, relay: Relay):
        self.name, self.relay = name, relay
        self.identity = IdentityKeyPair()
        self.store = PrekeyStore(self.identity)
        self.sessions: dict[str, Ratchet] = {}
        self._init: dict[str, InitialHeader] = {}          # пока пир не ответил, шлём init в каждом сообщении
        self.known: dict[str, IdentityPublic] = {}         # TOFU: запомненные ключи собеседников
        self._owner: dict[IdentityPublic, str] = {}        # обратная связь: один ключ идентичности - одно имя
        self.errors: list[Exception] = []

    def publish_prekeys(self, n_opks: int = 5):
        self.relay.publish(self.name, self.identity.public, self.store.spk_id, self.store.spk, self.store.spk_sig,
                           self.store.new_opks(n_opks))

    def _trust(self, peer: str, ident: IdentityPublic):
        known = self.known.get(peer)
        if known is not None and known != ident:
            raise IdentityChanged(f"ключи {peer} изменились: сверьте safety number")
        # Поле "from" конверта не аутентифицировано: relay может переподписать чужое сообщение другим именем.
        # Защита: ключ, уже привязанный к одному имени, нельзя привязать к другому.
        owner = self._owner.get(ident)
        if owner is not None and owner != peer:
            raise IdentityChanged(f"этот ключ принадлежит {owner}, а не {peer}: возможна подмена отправителя")
        self.known[peer] = ident
        self._owner[ident] = peer

    def send(self, peer: str, plaintext: bytes):
        if peer not in self.sessions:
            bundle = self.relay.fetch_bundle(peer)
            self._trust(peer, bundle.identity)
            sk, ad, init = x3dh_initiate(self.identity, bundle)
            self.sessions[peer] = Ratchet.init_alice(sk, bundle.spk, ad)
            self._init[peer] = init
        header, ct = self.sessions[peer].encrypt(plaintext)
        self.relay.post(peer, encode_envelope(self.name, self._init.get(peer), header, ct))

    def receive_all(self) -> list[tuple[str, bytes]]:
        out = []
        for raw in self.relay.poll(self.name):
            try:
                sender, init, header, ct = decode_envelope(raw)
                if sender not in self.sessions:
                    if init is None:
                        raise DecryptionError("нет сессии и нет init-заголовка")
                    self._trust(sender, init.identity)
                    sk, ad = x3dh_respond(self.store, init)
                    self.sessions[sender] = Ratchet.init_bob(sk, *self.store.spk_keys(init.spk_id), ad)
                pt = self.sessions[sender].decrypt(header, ct)
                self._init.pop(sender, None)               # ответ получен: init больше не нужен
                out.append((sender, pt))
            except E2EEError as e:
                self.errors.append(e)
        return out
