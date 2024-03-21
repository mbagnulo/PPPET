## RELAY_COMMAND_ESTABLISH_RENDEZVOUS 

Extracted from https://spec.torproject.org/rend-spec/rendezvous-protocol.html#the-rendezvous-protocol

Before connecting to a hidden service, the client first builds a circuit to an arbitrarily chosen Tor node (known as the rendezvous point), and sends an 
ESTABLISH_RENDEZVOUS message. The hidden service later connects to the same node and sends a RENDEZVOUS message. Once this has occurred, the relay forwards 
the contents of the RENDEZVOUS message to the client, and joins the two circuits together.


Establishing a rendezvous point

The client sends the rendezvous point a RELAY_COMMAND_ESTABLISH_RENDEZVOUS message containing a 20-byte value.

RENDEZVOUS_COOKIE [20 bytes]


The rendezvous cookie is an arbitrary 20-byte value, chosen randomly by the client. The client SHOULD choose a new rendezvous cookie for each new connection attempt. 
If the rendezvous cookie is already in use on an existing circuit, the rendezvous point should reject it and destroy the circuit.

Upon receiving an ESTABLISH_RENDEZVOUS message, the rendezvous point associates the cookie with the circuit on which it was sent. 
It replies to the client with an empty RENDEZVOUS_ESTABLISHED message to indicate success. Clients MUST ignore any extra bytes in a RENDEZVOUS_ESTABLISHED message.

The client MUST NOT use the circuit which sent the message for any purpose other than rendezvous with the given location-hidden service.
