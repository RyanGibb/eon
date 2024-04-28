type t = Eio.Flow.two_way_ty Eio.Resource.t

val create : inc:Cstruct_stream.t -> out:Cstruct_stream.t -> t
