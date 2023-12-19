let rec trim_leading_null s =
  if String.length s = 0 then
    s
  else if String.get s 0 = '\000' then
    trim_leading_null (String.sub s 1 (String.length s - 1))
  else
    s

(** byte reversing *)
let rev s =
  let slen = String.length s in
  String.init slen (fun idx -> String.get s (slen - succ idx))

let urlencode =
  Base64.encode_string ~pad:false ~alphabet:Base64.uri_safe_alphabet

let urldecode s =
  Base64.decode ~pad:false ~alphabet:Base64.uri_safe_alphabet s

let urlencodez z = urlencode (trim_leading_null (rev (Z.to_bits z)))

let urldecodez z64 =
  Result.map (fun bits -> Z.of_bits (rev bits)) (urldecode z64)

