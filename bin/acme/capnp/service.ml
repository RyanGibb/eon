module Api = Service_api.MakeRPC (Capnp_rpc_lwt)
open Capnp_rpc_lwt

module CertManager = struct
  let local callback =
    let module CertManager = Api.Service.CertManager in
    CertManager.local @@ object
      inherit CertManager.service

      method register_impl params release_param_caps =
        let open CertManager.Register in
        callback (match Params.success_get params with
        | true -> Ok (Params.cert_get params, Params.key_get params)
        | false -> Error (`Cert (Params.error_get params)));
        release_param_caps ();
        let response, _results =
          Service.Response.create Results.init_pointer
        in
        Service.return response

    end

  let register t success error cert key =
    let open Api.Client.CertManager.Register in
    let request, params = Capability.Request.create Params.init_pointer in
    Params.success_set params success;
    Params.error_set params error;
    Params.cert_set params (match cert with
    | None -> ""
    | Some v -> v |> X509.Certificate.encode_pem_multiple |> Cstruct.to_string);
    Params.key_set params (match key with
    | None -> ""
    | Some v -> v |> X509.Private_key.encode_pem |> Cstruct.to_string);
    Capability.call_for_unit t method_id request
end

module Domain = struct
  let local domain provision_cert =
    let module Domain = Api.Service.Domain in
    Domain.local @@ object
      inherit Domain.service

      method cert_impl params release_param_caps =
        let open Domain.Cert in
        let email = Params.email_get params; in
        let org = Params.org_get params; in
        let subdomain = Params.subdomain_get params; in
        let mgr = Option.get (Params.mgr_get params); in
        release_param_caps ();
        Eio.traceln "Domain.bind(email=%s, org=%s, subdomain=%s) domain=%s"
          email org subdomain(Domain_name.to_string domain);
        let response, _results =
          Service.Response.create Results.init_pointer
        in
        let callback_result = (try (
          let domain = Domain_name.append_exn domain (Domain_name.of_string_exn subdomain) in
          let cert, _account_key, private_key, _csr = provision_cert ~email ~org ~domain in
          CertManager.register mgr true "" (Some cert) (Some private_key)
        ) with
        | Tls_le.Le_error msg ->
          CertManager.register mgr false msg None None
        | e ->
          let msg = Printexc.to_string e in
          CertManager.register mgr false msg None None
        ) in
        (match callback_result with
        | Ok () -> ()
        | Error (`Capnp e) ->
          Eio.traceln "%a" Capnp_rpc.Error.pp e);
        (* TODO register renewal process *)
        Service.return response
    end

  let cert t ~email ~org ~subdomain mgr =
    let open Api.Client.Domain.Cert in
    let request, params = Capability.Request.create Params.init_pointer in
    Params.email_set params email;
    Params.org_set params org;
    Params.subdomain_set params (Domain_name.to_string subdomain);
    Params.mgr_set params (Some mgr);
    Capability.call_for_unit t method_id request
end

module Root = struct
  let local provision_cert =
    let module Root = Api.Service.Root in
    Root.local @@ object
      inherit Root.service

      method bind_impl params release_param_caps =
        let open Root.Bind in
        let domain = Params.domain_name_get params; in
        release_param_caps ();
        Eio.traceln "Service.bind(domain='%s')" domain;
        let response, results =
          Service.Response.create Results.init_pointer
        in
        (match Domain_name.of_string domain with
        | Error (`Msg e) ->
          Eio.traceln "Root error parsing domain: %s" e
        | Ok domain ->
          Results.domain_set results (Some (Domain.local domain provision_cert)));
        Service.return response
    end

  let bind t domain =
    let open Api.Client.Root.Bind in
    let request, params = Capability.Request.create Params.init_pointer in
    Params.domain_name_set params (Domain_name.to_string domain);
    Capability.call_for_caps t method_id request Results.domain_get_pipelined
end
