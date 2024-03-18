# Statement we want to prove:

KP_hs_id used to generate KP_hs_blind_id is contained in HSOK

# Public inputs:
- HSOK - Allow-list in the form of Merkle tree that contains the KP_hs_id for al the HS that HSDIR instance is willing to serve.
- KP_hs_blinded_id: key used to identify the HS in the DHT
- Period_number: current period number
- Period_length: current period lenght

# Private inputs:
- KP_hs_id
- HSOK tree path to KP_hs_id
- s: optional secret

