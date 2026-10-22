import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
from e2ee import safety_number
from relay import Relay, Client

relay = Relay()
alice, bob = Client("alice", relay), Client("bob", relay)
bob.publish_prekeys()
print("1. Алиса пишет Бобу, который офлайн (X3DH по prekey-bundle)")
alice.send("bob", "привет, Боб".encode())
print("2. Bob получает:", [(s, m.decode()) for s, m in bob.receive_all()])
bob.send("alice", "привет, Алиса".encode()); print("3. Alice получает:", [(s, m.decode()) for s, m in alice.receive_all()])
print("4. Safety number:", safety_number(alice.identity.public, bob.identity.public))
for i in range(3):
    alice.send("bob", b"msg %d" % i)
print("5. Relay видел только:", relay.seen[-1][:90], b"...")
print("6. Bob:", bob.receive_all())
