
open Ciphersuite

type connection_end = Server | Client

type cipher_block_or_stream_type = Block | Stream

type security_parameters = {
  entity              : connection_end;

  cipher              : encryption_algorithm;
  block_or_stream     : cipher_block_or_stream_type;
  mac                 : hash_algorithm;

  master_secret       : Cstruct.t;
  client_random       : Cstruct.t;
  server_random       : Cstruct.t;

  hash_size           : int;
  key_size            : int;
  key_material_length : int;
  cipher_IV_size      : int
}

type connection_state = {
  cipher_state : Cstruct.t;
  mac_secret : Cstruct.t;
  sequence_number : int; (*uint64 says the spec*)

  client_write_MAC_secret : Cstruct.t; (*security_parameters.hash_size*)
  server_write_MAC_secret : Cstruct.t; (*security_parameters.hash_size*)
  client_write_key : Cstruct.t; (*security_parameters.key_material_length*)
  server_write_key : Cstruct.t; (*security_parameters.key_material_length*)
  client_write_IV : Cstruct.t; (*security_parameters.cipher_IV_size*)
  server_write_IV : Cstruct.t (*security_parameters.cipher_IV_size*)
}

