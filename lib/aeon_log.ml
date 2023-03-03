
let log_level_0 _fmt _direction _addr _buf = ()

let log_helper fmt direction addr buf log_packet =
  let log_transmssion direction addr =
    (match direction with
    | `Rx -> Format.fprintf fmt "<-"
    | `Tx -> Format.fprintf fmt "->");
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
  | Ok packet -> log_packet packet;
  Format.print_space (); Format.print_space ();
  Format.print_flush ()

let log_level_1 fmt direction addr buf =
  let log_packet (packet : Dns.Packet.t) =
    Format.fprintf fmt "question %a@ data %a@"
      Dns.Packet.Question.pp packet.question
      Dns.Packet.pp_data packet.data
  in
  log_helper fmt direction addr buf log_packet

let log_level_2 fmt direction addr buf =
  let log_packet = Dns.Packet.pp fmt in
  log_helper fmt direction addr buf log_packet

let log_level_3 fmt direction addr buf =
  let log_transmssion direction addr =
    (match direction with
    | `Rx -> Format.fprintf fmt "<-"
    | `Tx -> Format.fprintf fmt "->");
    Format.print_space ();
    Eio.Net.Sockaddr.pp fmt addr;
    Format.print_space ()
  in
  log_transmssion direction addr;
  Format.print_flush ();
  Cstruct.hexdump buf;
  Format.print_space ();
  Format.print_flush ();
