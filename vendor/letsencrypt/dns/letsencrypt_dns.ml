let src = Logs.Src.create "letsencrypt.dns" ~doc:"let's encrypt library"
module Log = (val Logs.src_log src : Logs.LOG)

let dns_solver writef =
  let solve_challenge ~token:_ ~key_authorization domain =
    let solution = Letsencrypt.sha256_and_base64 key_authorization in
    let domain_name = Domain_name.prepend_label_exn domain "_acme-challenge" in
    writef domain_name solution
  in
  { Letsencrypt.Client.typ = `Dns ; solve_challenge }

let print_dns =
  let solve domain solution =
    Log.warn (fun f -> f "Setup a TXT record for %a to return %s and press enter to continue"
                 Domain_name.pp domain solution);
    ignore (read_line ());
    Ok ()
  in
  dns_solver solve

let nsupdate ?proto id now out ?recv ~zone ~keyname key =
  let open Dns in
  let nsupdate name record =
    Log.info (fun m -> m "solving dns by update to! %a (name %a)"
                 Domain_name.pp zone Domain_name.pp name);
    let zone = Packet.Question.create zone Rr_map.Soa
    and update =
      let up =
        Domain_name.Map.singleton name
          [
            Packet.Update.Remove (Rr_map.K Txt) ;
            Packet.Update.Add Rr_map.(B (Txt, (3600l, Txt_set.singleton record)))
      ]
      in
      (Domain_name.Map.empty, up)
    and header = (id, Packet.Flags.empty)
    in
    let packet = Packet.create header zone (`Update update) in
    match Dns_tsig.encode_and_sign ?proto packet (now ()) key keyname with
    | Error s -> Error(`Msg (Fmt.to_to_string Dns_tsig.pp_s s))
    | Ok (data, mac) ->
      out data |> function
      | Error err -> Error err
      | Ok () ->
        match recv with
        | None -> Ok ()
        | Some recv -> recv () |> function
          | Error e -> Error e
          | Ok data ->
            match Dns_tsig.decode_and_verify (now ()) key keyname ~mac data with
            | Error e ->
              Error (`Msg (Fmt.str "decode and verify error %a" Dns_tsig.pp_e e))
            | Ok (res, _, _) ->
              match Packet.reply_matches_request ~request:packet res with
              | Ok _ -> Ok ()
              | Error mismatch ->
                Error (`Msg (Fmt.str "error %a expected reply to %a, got %a"
                               Packet.pp_mismatch mismatch
                               Packet.pp packet Packet.pp res))
  in
  dns_solver nsupdate
