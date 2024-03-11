module Api = Service_api.MakeRPC (Capnp_rpc_lwt)
open Capnp_rpc_lwt

module CertCallback = struct
  let local callback =
    let module CertCallback = Api.Service.CertCallback in
    CertCallback.local @@ object
      inherit CertCallback.service

      method register_impl params release_param_caps =
        let open CertCallback.Register in
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
    let open Api.Client.CertCallback.Register in
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
  let rec local domain provision_cert =
    let module Domain = Api.Service.Domain in
    Domain.local @@ object
      inherit Domain.service
      
      val account_key_r = ref @@ None
      val private_key_r = ref @@ None

      method get_name_impl _params release_param_caps =
        let open Domain.GetName in
        release_param_caps();
        let response, results = Service.Response.create Results.init_pointer in
        Results.name_set results (Domain_name.to_string domain);
        Service.return response

      method cert_impl params release_param_caps =
        let open Domain.Cert in
        let email = Params.email_get params; in
        let org = Params.org_get params; in
        let subdomain = Params.subdomain_get params; in
        let mgr = Option.get (Params.cert_callback_get params); in
        release_param_caps ();
        Eio.traceln "Domain.bind(email=%s, org=%s, subdomain=%s) domain=%s"
          email org subdomain (Domain_name.to_string domain);
        let response, _results =
          Service.Response.create Results.init_pointer
        in
        let callback_result = (try (
          let domain = Domain_name.append_exn domain (Domain_name.of_string_exn subdomain) in
          let cert, account_key, private_key, _csr = provision_cert ?account_key:(!account_key_r) ?private_key:(!private_key_r) ~email ~org domain in
          account_key_r := Some account_key;
          private_key_r := Some private_key;
          CertCallback.register mgr true "" (Some cert) (Some private_key)
        ) with
        | Tls_le.Le_error msg ->
          CertCallback.register mgr false msg None None
        | e ->
          let msg = Printexc.to_string e in
          CertCallback.register mgr false msg None None
        ) in
        (match callback_result with
        | Ok () -> ()
        | Error (`Capnp e) ->
          Eio.traceln "%a" Capnp_rpc.Error.pp e);
        (* TODO register renewal process *)
        Service.return response

      method delegate_impl params release_param_caps =
        let open Domain.Delegate in
        let subdomain = Params.subdomain_get params; in
        release_param_caps ();
        Eio.traceln "Service.delegate(subdomain='%s')" subdomain;
        let response, results =
          Service.Response.create Results.init_pointer
        in
        (match Domain_name.of_string subdomain with
        | Error (`Msg e) ->
          Eio.traceln "Domain.delegate error parsing domain: %s" e
        | Ok subdomain ->
          let domain = Domain_name.append_exn domain subdomain in
          Results.domain_set results (Some (local domain provision_cert)));
        Service.return response

      method update_impl params release_param_caps =
        let open Domain.Update in
        let _prereqs = Params.prereqs_get params; in
        let _updates = Params.updates_get params; in
        release_param_caps ();
        (* TODO update *)
        let response, _results =
          Service.Response.create Results.init_pointer
        in
        Service.return response

    end

  let cert t ~email ~org ~subdomain cert_callback =
    let open Api.Client.Domain.Cert in
    let request, params = Capability.Request.create Params.init_pointer in
    Params.email_set params email;
    Params.org_set params org;
    Params.subdomain_set params (Domain_name.to_string subdomain);
    Params.cert_callback_set params (Some cert_callback);
    Capability.call_for_unit t method_id request

  let delegate t domain =
    let open Api.Client.Domain.Delegate in
    let request, params = Capability.Request.create Params.init_pointer in
    Params.subdomain_set params (Domain_name.to_string domain);
    Capability.call_for_caps t method_id request Results.domain_get_pipelined
end

module Zone = struct
  let local provision_cert =
    let module Zone = Api.Service.Zone in
    Zone.local @@ object
      inherit Zone.service

      method init_impl params release_param_caps =
        let open Zone.Init in
        let domain = Params.name_get params; in
        release_param_caps ();
        Eio.traceln "Service.init(domain='%s')" domain;
        let response, results =
          Service.Response.create Results.init_pointer
        in
        (match Domain_name.of_string domain with
        | Error (`Msg e) ->
          Eio.traceln "Zone error parsing domain: %s" e
        | Ok domain ->
          Results.domain_set results (Some (Domain.local domain provision_cert)));
        Service.return response
    end

  let init t domain =
    let open Api.Client.Zone.Init in
    let request, params = Capability.Request.create Params.init_pointer in
    Params.name_set params (Domain_name.to_string domain);
    Capability.call_for_caps t method_id request Results.domain_get_pipelined
end
