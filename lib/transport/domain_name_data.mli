val max_encoded_len : int
val decode : String.t -> [ `raw ] Domain_name.t -> (Cstruct.t * [ `raw ] Domain_name.t) option
val encode : [ `raw ] Domain_name.t -> Cstruct.t -> [ `raw ] Domain_name.t
