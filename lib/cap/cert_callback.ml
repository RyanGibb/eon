open Raw
open Capnp_rpc_lwt

let local callback =
  let module CertCallback = Api.Service.CertCallback in
  CertCallback.local
  @@ object
       inherit CertCallback.service

       method register_impl params release_param_caps =
         let open CertCallback.Register in
         callback
           (match Params.success_get params with
           | true ->
               Ok
                 ( Params.cert_get params,
                   Params.key_get params,
                   Params.renewed_get params )
           | false -> Error (`Remote (Params.error_get params)));
         release_param_caps ();
         let response, _results =
           Service.Response.create Results.init_pointer
         in
         Service.return response
     end

let register t success error cert key renewed =
  let open Api.Client.CertCallback.Register in
  let request, params = Capability.Request.create Params.init_pointer in
  Params.success_set params success;
  Params.error_set params error;
  Params.cert_set params
    (match cert with
    | None -> ""
    | Some v -> v |> X509.Certificate.encode_pem_multiple |> Cstruct.to_string);
  Params.key_set params
    (match key with
    | None -> ""
    | Some v -> v |> X509.Private_key.encode_pem |> Cstruct.to_string);
  Params.renewed_set params renewed;
  Capability.call_for_unit t method_id request
