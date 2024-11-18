open Lwt.Infix

let msgf fmt = Fmt.kstr (fun msg -> `Msg msg) fmt

let pp_error ppf = function
  | #Httpaf.Status.t as code -> Httpaf.Status.pp_hum ppf code
  | `Exn exn -> Fmt.pf ppf "exception %s" (Printexc.to_string exn)

module Make
    (Time : Mirage_time.S)
    (Stack : Tcpip.Stack.V4V6)
    (Random : Mirage_crypto_rng_mirage.S)
    (Mclock : Mirage_clock.MCLOCK)
    (Pclock : Mirage_clock.PCLOCK) =
struct
  module Paf = Paf_mirage.Make (Stack.TCP)
  module LE = LE.Make (Time) (Stack)

  let get_certificates ~yes_my_port_80_is_reachable_and_unused:stackv4v6
      ~production config http =
    Paf.init ~port:80 (Stack.tcp stackv4v6) >>= fun t ->
    let `Initialized web_server, stop_web_server =
      let request_handler _ = LE.request_handler in
      let error_handler _dst ?request err _ =
        Logs.err (fun m ->
            m "error %a while processing request %a" pp_error err
              Fmt.(option ~none:(any "unknown") Httpaf.Request.pp_hum)
              request) in
      let stop = Lwt_switch.create () in
      (Paf.serve ~stop (Paf.http_service ~error_handler request_handler) t, stop)
    in
    Logs.info (fun m -> m "listening on 80/HTTP (let's encrypt provisioning)") ;
    let provision_certificate =
      (* XXX(dinosaure): we assume that [provision_certificate] terminates.
         By this way, we are able to stop our web-server and resolve our
         [Lwt.both]. *)
      LE.provision_certificate ~production config http >>= fun v ->
      Lwt_switch.turn_off stop_web_server >>= fun () -> Lwt.return v in
    Lwt.both web_server provision_certificate >|= snd

  let redirect config tls_port reqd =
    let request = Httpaf.Reqd.request reqd in
    let host =
      match Httpaf.Headers.get request.Httpaf.Request.headers "host" with
      | Some host -> host
      | None -> Domain_name.to_string config.LE.hostname in
    let response =
      let port = if tls_port = 443 then None else Some tls_port in
      let uri =
        Fmt.str "https://%s%a%s" host
          Fmt.(option ~none:nop (fmt ":%d"))
          port request.Httpaf.Request.target in
      let headers =
        Httpaf.Headers.of_list [ ("location", uri); ("connection", "close") ]
      in
      Httpaf.Response.create ~headers `Moved_permanently in
    Httpaf.Reqd.respond_with_string reqd response ""

  let info =
    let module R = (val Mimic.repr Paf.tls_protocol) in
    let alpn_of_tls_connection (_edn, flow) =
      match Paf.TLS.epoch flow with
      | Ok { Tls.Core.alpn_protocol; _ } -> alpn_protocol
      | Error _ -> None in
    let peer_of_tls_connection (edn, _flow) = edn in
    (* XXX(dinosaure): [TLS]/[ocaml-tls] should let us to project the underlying
     * [flow] and apply [TCP.dst] on it.
     * Actually, we did it with the [TLS] module. *)
    let injection (_edn, flow) = R.T flow in
    {
      Alpn.alpn = alpn_of_tls_connection;
      Alpn.peer = peer_of_tls_connection;
      Alpn.injection;
    }

  let with_lets_encrypt_certificates ?(port = 443) ?(alpn_protocols= [ "http/1.1"; "h2" ]) stackv4v6 ~production config
      client handler =
    let certificates = ref None in
    let stop_http_server = Lwt_switch.create () in
    let stop_alpn_server = Lwt_switch.create () in
    let mutex = Lwt_mutex.create () in

    let rec fill_certificates () =
      LE.provision_certificate ~production config client >>= function
      | Error _ as err ->
          Lwt_switch.turn_off stop_http_server >>= fun () ->
          Lwt_switch.turn_off stop_alpn_server >>= fun () -> Lwt.return err
      | Ok v ->
          Lwt_mutex.with_lock mutex (fun () ->
              certificates := Some v ;
              Lwt.return_unit)
          >>= fun () ->
          (* TODO(dinosaure): should we [reneg] all previous connections? *)
          Time.sleep_ns (Duration.of_day 80) >>= fill_certificates in

    let handshake tcp =
      Lwt_mutex.with_lock mutex (fun () -> Lwt.return !certificates)
      >>= function
      | None -> Lwt.return_error `No_certificates
      | Some certificates -> (
          match Tls.Config.server ~alpn_protocols ~certificates () with
          | Error `Msg msg -> Lwt.return_error (`Msg msg)
          | Ok cfg ->
            Paf.TLS.server_of_flow cfg tcp >>= function
            | Ok flow -> Lwt.return_ok (Paf.TCP.dst tcp, flow)
            | Error `Closed -> Lwt.return_error (`Write `Closed)
            | Error err ->
              let err = msgf "%a" Paf.TLS.pp_write_error err in
              Paf.TCP.close tcp >>= fun () -> Lwt.return_error err) in
    let module R = (val Mimic.repr Paf.tls_protocol) in
    let request flow edn reqd protocol =
      match flow with
      | R.T flow -> handler.Alpn.request flow edn reqd protocol
      | _ -> assert false in

    let alpn_service =
      Alpn.service info { handler with request } handshake Paf.accept Paf.close
    in
    let http_service =
      let request_handler _ edn reqd =
        let request = Httpaf.Reqd.request reqd in
        match String.split_on_char '/' request.Httpaf.Request.target with
        | [ ""; _p1; _p2; _token ] -> LE.request_handler edn reqd
        | _ -> redirect config port reqd in
      let error_handler _dst ?request err _ =
        Logs.err (fun m ->
            m "error %a while processing request %a" pp_error err
              Fmt.(option ~none:(any "unknown") Httpaf.Request.pp_hum)
              request) in
      Paf.http_service ~error_handler request_handler in

    Paf.init ~port:80 (Stack.tcp stackv4v6) >>= fun http ->
    Paf.init ~port (Stack.tcp stackv4v6) >>= fun alpn ->
    let (`Initialized http_server) =
      Paf.serve ~stop:stop_http_server http_service http in
    let (`Initialized alpn_server) =
      Paf.serve ~stop:stop_alpn_server alpn_service alpn in
    Lwt.both (fill_certificates ()) (Lwt.join [ http_server; alpn_server ])
    >>= function
    | (Error _ as err), () -> Lwt.return err
    | _ -> Lwt.return_ok ()
end
