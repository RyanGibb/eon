open Eio.Std
open Capnp_rpc_lwt
open Capnp_rpc_net
module File_store = Capnp_rpc_unix.File_store
module Store = Store.Make (Capnp.BytesMessage)

type loader =
  [ `Domain_debb01f25d5fee15 ] Sturdy_ref.t ->
  name:[ `raw ] Domain_name.t ->
  Restorer.resolution

type t = {
  store : Store.Reader.SavedService.struct_t File_store.t;
  loader : loader Promise.t;
  make_sturdy : Restorer.Id.t -> Uri.t;
}

let hash _ = `SHA256
let make_sturdy t = t.make_sturdy

let save t ~digest name =
  let open Store.Builder in
  let service = SavedService.init_root () in
  let domain = SavedService.domain_init service in
  SavedDomain.name_set domain (Domain_name.to_string name);
  File_store.save t.store ~digest @@ SavedService.to_reader service

let save_new t ~name =
  let id = Restorer.Id.generate () in
  let digest = Restorer.Id.digest (hash t) id in
  save t ~digest name;
  id

let load t sr digest =
  match File_store.load t.store ~digest with
  | None -> Restorer.unknown_service_id
  | Some saved_service ->
      let domain = Store.Reader.SavedService.domain_get saved_service in
      let name =
        Domain_name.of_string_exn (Store.Reader.SavedDomain.name_get domain)
      in
      let sr = Capnp_rpc_lwt.Sturdy_ref.cast sr in
      let loader = Promise.await t.loader in
      loader sr ~name

let create ~make_sturdy dir =
  let loader, set_loader = Promise.create () in
  if not (Eio.Path.is_directory dir) then Eio.Path.mkdir dir ~perm:0o755;
  let store = File_store.create dir in
  ({ store; loader; make_sturdy }, set_loader)
