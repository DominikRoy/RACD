!/bin/bash
(./../output/attestor server_name=localhost server_port=4433 ca_file=my_ca_localhost.crt crt_file=prover_localhost.crt key_file=prover_key.key programs_file=programs250.cbor &); sleep .2; ./../output/verifier server_name=localhost server_port=4433 ca_file=my_ca_localhost.crt crt_file=verifier_localhost.crt key_file=verifier_key.key swSelection_file=programs200.cbor; pkill attestor ;
