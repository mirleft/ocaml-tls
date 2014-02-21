
open Ciphersuite

type connection_end = Server | Client

type cipher_block_or_stream_type = Block | Stream

type security_parameters = {
  entity              : connection_end;

  cipher              : encryption_algorithm;
  block_or_stream     : cipher_block_or_stream_type;
  mac                 : hash_algorithm;

  master_secret       : string;
  client_random       : Cstruct.t;
  server_random       : Cstruct.t
}

let empty_server_security_parameters =
  { entity = Server;
    cipher = NULL;
    block_or_stream = Stream;
    mac = NULL;
    master_secret = "";
    client_random = Cstruct.create 0;
    server_random = Cstruct.create 0;
  }

let empty_client_security_parameters =
  { entity = Client;
    cipher = NULL;
    block_or_stream = Stream;
    mac = NULL;
    master_secret = "";
    client_random = Cstruct.create 0;
    server_random = Cstruct.create 0;
  }

type connection_state = {
(*   mutable cipher_state : Cstruct.t; *)
  sequence_number : int; (*uint64 says the spec*)
(*   mutable sequence_number : int; |+uint64 says the spec+| *)

  client_write_MAC_secret : string; (*security_parameters.hash_size*)
  server_write_MAC_secret : string; (*security_parameters.hash_size*)
  client_write_key : string; (*security_parameters.key_material_size*)
  server_write_key : string; (*security_parameters.key_material_size*)
(*  client_write_IV : string; (*security_parameters.cipher_IV_size*)
  server_write_IV : string (*security_parameters.cipher_IV_size*) *)
}

let empty_ctx =
  { sequence_number = 0 ;
    client_write_MAC_secret = "" ;
    server_write_MAC_secret = "" ;
    client_write_key = "" ;
    server_write_key = ""
  }

let needs_kex = function
  | DHE_DSS | DHE_RSA | DH_anon | ECDHE_ECDSA | ECDHE_RSA | ECDH_anon -> true
  | _ -> false

(* encryption_algorithm ->
   (key_material          : int, -- bytes from key_block to generate write keys
    iv_size               : int option, -- length of IV, None for stream ciphers
    block_size            : int option) -- decryption chunk size *)
let key_lengths = function
  | IDEA_CBC -> (16, Some 8, Some 8)
  | RC2_40_CBC -> (5, Some 8, Some 8)
  | RC4_40 -> (5, None, None)
  | RC4_128 -> (16, None, None)
  | DES_40_CBC -> (5, Some 8, Some 8)
  | DES_CBC -> (8, Some 8, Some 8)
  | TRIPLE_DES_EDE_CBC -> (24, Some 8, Some 8)
  | SEED_CBC -> (16, Some 16, Some 16)
  | AES_128_CBC -> (16, Some 16, Some 16)
  | AES_256_CBC -> (32, Some 16, Some 16)
(*  | AES_128_GCM
  | AES_256_GCM
  | AES_128_CCM
  | AES_256_CCM
  | AES_128_CCM_8
  | AES_256_CCM_8 *)
  | CAMELLIA_128_CBC -> (16, Some 16, Some 16)
  | CAMELLIA_256_CBC -> (32, Some 16, Some 16)
(*  | CAMELLIA_128_GCM
  | CAMELLIA_256_GCM
  | ARIA_128_GCM
  | ARIA_256_GCM
  | ARIA_128_CBC
  | ARIA_256_CBC *)
  | NULL -> (0, None, None)
  | _ -> assert false

let hash_length_padding = function
  | MD5 -> (16, 48)
  | SHA -> (20, 40)
  | SHA256 -> (32, 0)
(*  | SHA384 -> ()
  | SHA512 -> () *)
  | NULL -> (0, 0)
  | _ -> assert false
