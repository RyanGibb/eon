module Api = Cert_api.MakeRPC (Capnp_rpc_lwt)
open Capnp_rpc_lwt

let local provision_cert =
  let module Cert = Api.Service.Cert in
  Cert.local @@ object
    inherit Cert.service

    method request_impl params release_param_caps =
      let open Cert.Request in
      let email = Params.email_get params; in
      let org = Params.org_get params; in
      let domain = Params.domain_get params; in
      release_param_caps ();
      Eio.traceln "Recieved request: email '%s'; org '%s'; domain '%s'" email org domain;
      let response, results =
        Service.Response.create Results.init_pointer
      in
      (try (
        let cert, _account_key, _private_key, _csr = provision_cert ~email ~org ~domain in
        Results.success_set results true;
        Results.cert_set results (cert |> X509.Certificate.encode_pem_multiple |> Cstruct.to_string)
      ) with
      | Tls_le.Le_error msg -> (
        Results.success_set results false;
        Results.cert_set results msg)
      | e -> (
        let msg = Printexc.to_string e in
        Eio.traceln "%s" msg;
        Results.success_set results false
      ));
      Service.return response
  end

let request t ~account_key ~private_key ~email ~org ~domain =
  let open Api.Client.Cert.Request in
  let request, params = Capability.Request.create Params.init_pointer in
  Params.email_set params email;
  Params.org_set params org;
  Params.domain_set params domain;
  Params.account_key_set params account_key;
  Params.private_key_set params private_key;
  match Capability.call_for_value t method_id request with
  | Error e -> Error e
  | Ok results ->
    match Results.success_get results with
    | true -> Ok (Results.cert_get results)
    | false -> Error (`Cert (Results.error_get results))
