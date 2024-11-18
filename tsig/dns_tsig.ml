(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Dns

let src = Logs.Src.create "dns_tsig" ~doc:"DNS tsig"
module Log = (val Logs.src_log src : Logs.LOG)

let algorithm_to_nc = function
  | Tsig.SHA1 -> `SHA1
  | Tsig.SHA224 -> `SHA224
  | Tsig.SHA256 -> `SHA256
  | Tsig.SHA384 -> `SHA384
  | Tsig.SHA512 -> `SHA512

let compute_tsig name tsig ~key buf =
  let raw_name = Domain_name.raw name in
  let h = (algorithm_to_nc tsig.Tsig.algorithm :> Digestif.hash')
  and data = Tsig.encode_raw raw_name tsig
  in
  let module H = (val (Digestif.module_of_hash' h)) in
  H.hmac_string ~key (buf ^ data) |> H.to_raw_string

let ( let* ) = Result.bind

let guard p err = if p then Ok () else Error err

(* TODO: should name compression be done?  atm it's convenient not to do it *)
let add_tsig ?max_size name tsig str =
  let buf = Bytes.of_string str in
  Bytes.set_uint16_be buf 10 (succ (Bytes.get_uint16_be buf 10)) ;
  let tsig = Tsig.encode_full name tsig in
  match max_size with
  | Some x when x - Bytes.length buf < String.length tsig -> None
  | _ -> Some (Bytes.unsafe_to_string buf ^ tsig)

let mac_to_prep = function
  | None -> ""
  | Some mac ->
    let l = Bytes.create 2 in
    Bytes.set_uint16_be l 0 (String.length mac) ;
    Bytes.unsafe_to_string l ^ mac

let sign ?mac ?max_size name tsig ~key p str =
  match Base64.decode key.Dnskey.key with
  | Error _ -> None
  | Ok key ->
    let prep = mac_to_prep mac in
    let mac = compute_tsig name tsig ~key (prep ^ str) in
    let tsig = Tsig.with_mac tsig mac in
    (* RFC2845 Sec 3.1: if TSIG leads to truncation, alter message:
       - header stays (truncated = true)!
       - only question is preserved
       - _one_ additional, the TSIG itself *)
    match add_tsig ?max_size name tsig str with
    | Some out -> Some (out, mac)
    | None ->
      match p.Packet.data with
      | #Packet.request ->
        Log.err (fun m -> m "dns_tsig sign: truncated, is a request, not doing anything") ;
        None
      | #Packet.reply as r ->
        Log.err (fun m -> m "dns_tsig sign: truncated reply %a, sending tsig error"
                    Packet.pp_reply r) ;
        let header =
          fst p.header, Packet.Flags.add `Truncation (snd p.header)
        in
        let rc = Packet.rcode_data r
        and op = Packet.opcode_data r
        in
        let p' = Packet.create header p.question (`Rcode_error (rc, op, None)) in
        let new_buf, off = Packet.encode `Udp p' in
        let tbs = String.sub new_buf 0 off in
        let mac = compute_tsig name tsig ~key (prep ^ tbs) in
        let tsig = Tsig.with_mac tsig mac in
        match add_tsig name tsig new_buf with
        | None ->
          Log.err (fun m -> m "dns_tsig sign failed query %a with tsig %a too big (max_size %a) truncated packet %a:@.%a"
                    Packet.pp p Tsig.pp tsig Packet.pp p'
                    Fmt.(option ~none:(any "none") int) max_size
                    Ohex.pp new_buf) ;
          None
        | Some out -> Some (out, mac)

let verify_raw ?mac now name ~key tsig tbs =
  let name = Domain_name.raw name in
  let* priv =
    Result.map_error
      (fun _ -> `Bad_key (name, tsig))
      (Base64.decode key.Dnskey.key)
  in
  let ac = String.get_int16_be tbs 10 in
  let tbs = Bytes.of_string tbs in
  Bytes.set_int16_be tbs 10 (pred ac) ;
  let tbs = Bytes.unsafe_to_string tbs in
  let prep = mac_to_prep mac in
  let computed = compute_tsig name tsig ~key:priv (prep ^ tbs) in
  let mac = tsig.Tsig.mac in
  let* () = guard (String.length mac = String.length computed) (`Bad_truncation (name, tsig)) in
  let* () = guard (String.equal computed mac) (* Eqaf? *) (`Invalid_mac (name, tsig)) in
  let* () = guard (Tsig.valid_time now tsig) (`Bad_timestamp (name, tsig, key)) in
  let* tsig =
    Option.to_result ~none:(`Bad_timestamp (name, tsig, key))
      (Tsig.with_signed tsig now)
  in
  Ok (tsig, mac)

let verify ?mac now p name ?key tsig tbs =
  let raw_name = Domain_name.raw name in
  match
    let* key =
      Option.to_result ~none:(`Bad_key (raw_name, tsig)) key
    in
    let* tsig, mac = verify_raw ?mac now raw_name ~key tsig tbs in
    Ok (tsig, mac, key)
  with
  | Ok x -> Ok x
  | Error e ->
    Log.err (fun m -> m "error %a while verifying %a" Tsig_op.pp_e e Packet.pp p);
    let answer : string option = match p.Packet.data with
      | #Packet.reply -> None
      | #Packet.request as r ->
        (* now we prepare a reply for the request! *)
        (* TODO not clear which flags to preserve *)
        let header = fst p.Packet.header, Packet.Flags.empty
        and opcode = Packet.opcode_data r
        in
        (* TODO: edns *)
        let answer = Packet.create header p.question (`Rcode_error (Rcode.NotAuth, opcode, None)) in
        let err, max_size = Packet.encode `Udp answer in
        let or_err f err = match f err with None -> Some err | Some x -> Some x in
        match e with
        | `Bad_key (name, tsig) ->
          let tsig = Tsig.with_error (Tsig.with_mac tsig String.empty) Rcode.BadKey in
          or_err (add_tsig ~max_size name tsig) err
        | `Invalid_mac (name, tsig) ->
          let tsig = Tsig.with_error (Tsig.with_mac tsig String.empty) Rcode.BadVersOrSig in
          or_err (add_tsig ~max_size name tsig) err
        | `Bad_truncation (name, tsig) ->
          let tsig = Tsig.with_error (Tsig.with_mac tsig String.empty) Rcode.BadTrunc in
          or_err (add_tsig ~max_size name tsig) err
        | `Bad_timestamp (name, tsig, key) ->
          let tsig = Tsig.with_error tsig Rcode.BadTime in
          match Tsig.with_other tsig (Some now) with
          | None -> Some err
          | Some tsig ->
            match sign ~max_size ~mac:tsig.Tsig.mac name tsig ~key answer err with
            | None -> Some err
            | Some (buf, _) -> Some buf
    in
    Error (e, answer)

type s = [ `Key_algorithm of Dnskey.t | `Tsig_creation | `Sign ]

let pp_s ppf = function
  | `Key_algorithm key -> Fmt.pf ppf "algorithm %a not supported for tsig" Dnskey.pp key
  | `Tsig_creation -> Fmt.pf ppf "failed to create tsig"
  | `Sign -> Fmt.pf ppf "failed to sign"

let encode_and_sign ?(proto = `Udp) ?mac p now key keyname =
  let b, _ = Packet.encode proto p in
  match Tsig.dnskey_to_tsig_algo key with
  | Error _ -> Error (`Key_algorithm key)
  | Ok algorithm -> match Tsig.tsig ~algorithm ~signed:now () with
    | None -> Error `Tsig_creation
    | Some tsig -> match sign ?mac (Domain_name.raw keyname) ~key tsig p b with
      | None -> Error `Sign
      | Some r -> Ok r

type e = [
  | `Decode of Packet.err
  | `Unsigned of Packet.t
  | `Crypto of Tsig_op.e
  | `Invalid_key of [ `raw ] Domain_name.t * [ `raw ] Domain_name.t
]

let pp_e ppf = function
  | `Decode err -> Fmt.pf ppf "decode %a" Packet.pp_err err
  | `Unsigned res -> Fmt.pf ppf "unsigned %a" Packet.pp res
  | `Crypto c -> Fmt.pf ppf "crypto %a" Tsig_op.pp_e c
  | `Invalid_key (key, used) ->
    Fmt.pf ppf "invalid key, expected %a, but %a was used"
      Domain_name.pp key Domain_name.pp used

let decode_and_verify now key keyname ?mac buf =
  let raw_keyname = Domain_name.raw keyname in
  match Packet.decode buf with
  | Error e -> Error (`Decode e)
  | Ok ({ Packet.tsig = None ; _ } as res) -> Error (`Unsigned res)
  | Ok ({ Packet.tsig = Some (name, tsig, tsig_off) ; _ } as res) when Domain_name.equal keyname name ->
    begin match verify_raw ?mac now raw_keyname ~key tsig (String.sub buf 0 tsig_off) with
      | Ok (_, mac) -> Ok (res, tsig, mac)
      | Error e -> Error (`Crypto e)
    end
  | Ok { Packet.tsig = Some (name, _, _) ; _ } -> Error (`Invalid_key (raw_keyname, name))
