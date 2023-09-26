type dir = Rx | Tx
type log = Format.formatter -> dir -> Eio.Net.Sockaddr.t -> Cstruct.t -> unit
type formattedLog = dir -> Eio.Net.Sockaddr.t -> Cstruct.t -> unit

let log_level_0 _fmt (_direction : dir) _addr _buf = ()

let log_helper fmt (direction : dir) addr buf log_packet =
  let log_transmssion (direction : dir) addr =
    (match direction with
    | Rx -> Format.fprintf fmt "<-"
    | Tx -> Format.fprintf fmt "->");
    Format.print_space ();
    Eio.Net.Sockaddr.pp fmt addr;
    Format.print_space ()
  in
  log_transmssion direction addr;
  match Dns.Packet.decode buf with
  | Error e ->
      Format.fprintf fmt "error decoding:";
      Dns.Packet.pp_err fmt e;
      Format.print_space ();
      Format.print_flush ()
  | Ok packet ->
      log_packet packet;
      Format.print_space ();
      Format.print_space ();
      Format.print_flush ()

let log_level_1 fmt (direction : dir) addr buf =
  let log_packet (packet : Dns.Packet.t) =
    let id, _flags = packet.header in
    Format.fprintf fmt "header %04X question %a@ data %a@" id
      Dns.Packet.Question.pp packet.question Dns.Packet.pp_data packet.data
  in
  log_helper fmt direction addr buf log_packet

let log_level_2 fmt (direction : dir) addr buf =
  let log_packet = Dns.Packet.pp fmt in
  log_helper fmt direction addr buf log_packet

let log_level_3 fmt (direction : dir) addr buf =
  let log_transmssion (direction : dir) addr =
    (match direction with
    | Rx -> Format.fprintf fmt "<-"
    | Tx -> Format.fprintf fmt "->");
    Format.print_space ();
    Eio.Net.Sockaddr.pp fmt addr;
    Format.print_space ()
  in
  log_transmssion direction addr;
  Format.print_flush ();
  Cstruct.hexdump buf;
  Format.print_space ();
  Format.print_flush ()

let get_log log_level =
  match log_level with
  | 0 -> log_level_0
  | 1 -> log_level_1
  | 2 -> log_level_2
  | 3 -> log_level_3
  | _ -> if log_level < 0 then log_level_0 else log_level_2
