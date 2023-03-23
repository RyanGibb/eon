
type handle_dns = Dns.proto -> Cstruct.t -> Cstruct.t list

let safe_decode buf =
  let open Dns in
  match Packet.decode buf with
  | Error (`Bad_edns_version _i) ->
    (* Log.err (fun m -> m "bad edns version error %u while decoding@.%a"
                 i Cstruct.hexdump_pp buf); *)
    Error Rcode.BadVersOrSig
  | Error (`Not_implemented (_off, _msg)) ->
    (* Log.err (fun m -> m "not implemented at %d: %s while decoding@.%a"
                off msg Cstruct.hexdump_pp buf); *)
    Error Rcode.NotImp
  | Error _e ->
    (* Log.err (fun m -> m "error %a while decoding, giving up@.%a"
                Packet.pp_err e Cstruct.hexdump_pp buf); *)
    (* rx_metrics (`Rcode_error (Rcode.FormErr, Opcode.Query, None)); *)
    Error Rcode.FormErr
  | Ok v ->
    (* rx_metrics v.Packet.data; *)
    Ok v

let find_glue trie names =
  Domain_name.Host_set.fold (fun name map ->
      match
        match Dns_trie.lookup_glue name trie with
        | Some v4, Some v6 -> Some Dns.Rr_map.(add A v4 (singleton Aaaa v6))
        | Some v4, None -> Some (Dns.Rr_map.singleton A v4)
        | None, Some v6 -> Some (Dns.Rr_map.singleton Aaaa v6)
        | None, None -> None
      with
      | None -> map
      | Some rrs -> Domain_name.Map.add (Domain_name.raw name) rrs map)
    names Domain_name.Map.empty
  
let authoritative = Dns.Packet.Flags.singleton `Authoritative

let err_flags = function
  | Dns.Rcode.NotAuth -> Dns.Packet.Flags.empty
  | _ -> authoritative

let lookup trie (name, typ) =
  let open Dns in
  (* TODO: should randomize answers + ad? *)
  let r = match typ with
    | `Any -> Dns_trie.lookup_any name trie
    | `K (Rr_map.K k) -> match Dns_trie.lookup_with_cname name k trie with
      | Ok (B (k, v), au) -> Ok (Rr_map.singleton k v, au)
      | Error e -> Error e
  in
  match r with
  | Ok (an, (au, ttl, ns)) ->
    let answer = Domain_name.Map.singleton name an in
    let authority =
      Name_rr_map.remove_sub (Name_rr_map.singleton au Ns (ttl, ns)) answer
    in
    let additional =
      let names =
        Rr_map.(fold (fun (B (k, v)) s ->
            Domain_name.Host_set.union (names k v) s)
            an ns)
      in
      Name_rr_map.remove_sub
        (Name_rr_map.remove_sub (find_glue trie names) answer)
        authority
    in
    Ok (authoritative, (answer, authority), Some additional)
  | Error (`Delegation (name, (ttl, ns))) ->
    let authority = Name_rr_map.singleton name Ns (ttl, ns) in
    Ok (Packet.Flags.empty, (Name_rr_map.empty, authority),
        Some (find_glue trie ns))
  | Error (`EmptyNonTerminal (zname, soa)) ->
    let authority = Name_rr_map.singleton zname Soa soa in
    Ok (authoritative, (Name_rr_map.empty, authority), None)
  | Error (`NotFound (zname, soa)) ->
    let authority = Name_rr_map.singleton zname Soa soa in
    Error (Rcode.NXDomain, Some (Name_rr_map.empty, authority))
  | Error `NotAuthoritative -> Error (Rcode.NotAuth, None)

let dns_handler ~trie = fun proto buf ->
  match safe_decode buf with
  | Error rcode ->
    let answer = Dns.Packet.raw_error buf rcode in
    (* Log.warn (fun m -> m "error %a while %a sent %a, answering with %a"
                 Rcode.pp rcode Ipaddr.pp ip Cstruct.hexdump_pp buf
                 Fmt.(option ~none:(any "no") Cstruct.hexdump_pp) answer); *)
    (* tx_metrics (`Rcode_error (rcode, Opcode.Query, None)); *)
    (match answer with None -> [] | Some err -> [ err ])
    (* let bytes =
      match Dns.Packet.decode buf with
      | Error _ -> None
      | Ok p ->
        match Domain_name.Map.find_opt (Domain_name.raw @@ Domain_name.(host_exn @@ of_string_exn "rpc.example.org")) p.additional with
        | None -> None
        | Some map ->
          match Dns.Rr_map.find Dns.Rr_map.Null map with
          | None -> None (* TODO process cnames *)
          | Some (_ttl, answer) ->
            match Dns.Rr_map.Null_set.choose_opt answer with
              | None -> None
              | Some bytes -> Eio.traceln "%s" @@ Hex.show @@ Hex.of_bytes bytes; Some bytes
    in *)
  | Ok p ->
      match p.Dns.Packet.data with
      | `Query ->
        let name, qtype = p.question in
        (match qtype with
        (* this won't happen, decoder constructs `Axfr *)
        | `Axfr | `Ixfr -> [] (* (Error (Rcode.NotImp, None)) *)
        | (`K _ | `Any) as k ->
          let flags, data, additional =
            match Domain_name.find_label name (fun s -> String.equal "rpc" s) with
            | None ->
              (match lookup trie (name, k) with
              | Ok (flags, data, additional) -> flags, `Answer data, additional
              | Error (rcode, data) ->
                err_flags rcode, `Rcode_error (rcode, Dns.Opcode.Query, data), None
              )
            | Some i ->
              let data_name = Domain_name.drop_label_exn ~rev:true ~amount:(Domain_name.count_labels name - i) name in
              let root = Domain_name.drop_label_exn ~amount:i name in
              Eio.traceln "%s" @@ Domain_name.to_string root;
              let data_array = Domain_name.to_array data_name in
              let data = String.concat "" (Array.to_list data_array) in
              Eio.traceln "%s" data;
              let message = Base64.decode_exn data in
              Eio.traceln "%s" message;

              let reply =
                let rev x =
                  let len = String.length x in
                  String.init len (fun n -> String.get x (len - n - 1))
                in
                rev message
              in

              let data = Base64.encode_exn reply in
              let authority = Domain_name.to_string root in
              assert (String.length data + String.length authority < 255);
              let rec segment_string string =
                let max_len = 63 in
                let len = String.length string in
                if len > max_len then
                  let segment = String.sub string 0 max_len  in
                  let string = String.sub string max_len (len - max_len) in
                  let list = segment_string string in
                  segment :: list
                else
                  [ string ]
              in
              Eio.traceln "%s" data;
              let data_name = Array.of_list @@ segment_string data in
              let name_array = Array.append (Domain_name.to_array root) data_name in
              let hostname = Domain_name.of_array name_array in

              let flags = authoritative in
              (* typ *)
              let rr = Dns.Rr_map.singleton Dns.Rr_map.Cname (1l, hostname) in
              let answer = Domain_name.Map.singleton name rr in
              let authority = Dns.Name_rr_map.empty in (* Name_rr_map.remove_sub (Name_rr_map.singleton au Ns (ttl, ns)) answer *)
              let data = `Answer (answer, authority) in
              let additional = None in
              flags, data, additional
            in
            
              let max_size, _edns = Dns.Edns.reply p.edns in
              let answer = Dns.Packet.create ?additional (fst p.header, flags) p.question data in
              let answer = Dns.Packet.with_edns answer answer.edns in
              let packet, _size = Dns.Packet.encode ?max_size proto answer in
              [ packet ];
        )
      | _ -> []

let udp_listen log handle_dns sock =
  (* Support queries of up to 4kB.
     The 512B limit described in rfc1035 section 2.3.4 is outdated) *)
  let buf = Cstruct.create 4096 in
  while true do
    let addr, size = Eio.Net.recv sock buf in
    let trimmedBuf = Cstruct.sub buf 0 size in
    let addr = Util.sockaddr_of_sockaddr_datagram addr in
    log Dns_log.Rx addr trimmedBuf;
    let answers = handle_dns `Udp trimmedBuf in
    List.iter (fun b -> log Dns_log.Tx addr b; Eio.Net.send sock addr b) answers
  done

type connection_handler = Eio.Net.stream_socket -> Eio.Net.Sockaddr.stream -> unit

  let tcp_handle log handle_dns =
    let connection_handler sock addr =
      (* Persist connection until EOF, rfc7766 section 6.2.1 *)
      try
        while true do
          (* Messages sent over TCP have a 2 byte prefix giving the message length, rfc1035 section 4.2.2 *)
          let prefix = Cstruct.create 2 in
          Eio.Flow.read_exact sock prefix;
          let len = Cstruct.BE.get_uint16 prefix 0 in
          let buf = Cstruct.create len in
          Eio.Flow.read_exact sock buf;
          let addr = Util.sockaddr_of_sockaddr_stream addr in
          log Dns_log.Rx addr buf;
          let answers = handle_dns `Tcp buf in
          List.iter (fun b ->
            log Dns_log.Tx addr b;
            (* add prefix, described in rfc1035 section 4.2.2 *)
            let prefix = Cstruct.create 2 in
            Cstruct.BE.set_uint16 prefix 0 b.len;
            Eio.Flow.write sock [ prefix ; b ]
          ) answers
        done
      (* ignore EOF *)
      with End_of_file -> ()
  in connection_handler

let tcp_listen listeningSock connection_handler =
  while true do
    let on_error = Eio.traceln "Error handling connection: %a" Fmt.exn in
    Eio.Switch.run @@ fun sw ->
      Eio.Net.accept_fork ~sw listeningSock ~on_error connection_handler
  done
