open Eio.Std
open Capnp_rpc
open Capnp_rpc_net
module File_store = Capnp_rpc_unix.File_store
module Store = Store.Make (Capnp.BytesMessage)

type t = {
  store : Store.Reader.SavedService.struct_t File_store.t;
  domain_loader :
    ([ `Domain_debb01f25d5fee15 ] Sturdy_ref.t ->
    name:[ `raw ] Domain_name.t ->
    primary:string ->
    Restorer.resolution)
    Promise.t;
  secondary_loader :
    ([ `Secondary_88493aa33efcf56f ] Sturdy_ref.t ->
    name:[ `raw ] Domain_name.t ->
    Restorer.resolution)
    Promise.t;
  make_sturdy : Restorer.Id.t -> Uri.t;
}

let hash _ = `SHA256
let make_sturdy t = t.make_sturdy

let save_new_domain t ~name primary =
  let id = Restorer.Id.generate () in
  let digest = Restorer.Id.digest (hash t) id in
  let open Store.Builder in
  let service = SavedService.init_root () in
  let domain = SavedService.domain_init service in
  SavedDomain.name_set domain (Domain_name.to_string name);
  SavedDomain.primary_set domain (Result.get_ok @@ Primary.get_name primary);
  File_store.save t.store ~digest @@ SavedService.to_reader service;
  id

let save_new_secondary t ~name =
  let id = Restorer.Id.generate () in
  let digest = Restorer.Id.digest (hash t) id in
  let open Store.Builder in
  let service = SavedService.init_root () in
  let secondary = SavedService.secondary_init service in
  SavedSecondary.name_set secondary name;
  File_store.save t.store ~digest @@ SavedService.to_reader service;
  id

let load t sr digest =
  match File_store.load t.store ~digest with
  | None -> Restorer.unknown_service_id
  | Some saved_service -> (
      let open Store.Reader in
      match SavedService.get saved_service with
      | SavedService.Domain domain ->
          let name = Domain_name.of_string_exn (SavedDomain.name_get domain) in
          let primary = SavedDomain.primary_get domain in
          let sr = Capnp_rpc.Sturdy_ref.cast sr in
          let loader = Promise.await t.domain_loader in
          loader sr ~name ~primary
      | SavedService.Secondary secondary ->
          let name =
            Domain_name.of_string_exn (SavedSecondary.name_get secondary)
          in
          let sr = Capnp_rpc.Sturdy_ref.cast sr in
          let loader = Promise.await t.secondary_loader in
          loader sr ~name
      | SavedService.Undefined _ -> Restorer.unknown_service_id)

let create ~make_sturdy dir =
  let domain_loader, set_domain_loader = Promise.create () in
  let secondary_loader, set_secondary_loader = Promise.create () in
  if not (Eio.Path.is_directory dir) then Eio.Path.mkdir dir ~perm:0o755;
  let store = File_store.create dir in
  ( { store; domain_loader; secondary_loader; make_sturdy },
    set_domain_loader,
    set_secondary_loader )
