
(*
 * Monad core
 *)

(* Generic monad core; we could maybe import it from somewhere else. *)
module type Monad = sig
  type 'a t
  val return : 'a -> 'a t
  val bind   : 'a t -> ('a -> 'b t) -> 'b t
end

(* A larger monadic api over the core. *)
module type Monad_ext = sig
  type 'a t
  val return : 'a -> 'a t
  val (>>=)  : 'a t -> ('a -> 'b t) -> 'b t
  val (>|=)  : 'a t -> ('a -> 'b) -> 'b t
  val map    : ('a -> 'b) -> 'a t -> 'b t
  val sequence  : 'a t list -> 'a list t
  val sequence_ : 'a t list -> unit t
  val mapM      : ('a -> 'b t) -> 'a list -> 'b list t
  val mapM_     : ('a -> 'b t) -> 'a list -> unit t
  val foldM     : ('a -> 'b -> 'a t) -> 'a -> 'b list -> 'a t
end

module Monad_ext_make ( M : Monad ) :
  Monad_ext with type 'a t = 'a M.t =
struct
  type 'a t = 'a M.t
  let return = M.return
  let (>>=)  = M.bind
  let map f a = a >>= fun x -> return (f x)
  let (>|=) a f = map f a
  let rec sequence = function
    | []    -> return []
    | m::ms -> m >>= fun m' -> sequence ms >>= fun ms' -> return (m'::ms')
  let rec sequence_ = function
    | []    -> return ()
    | m::ms -> m >>= fun _ -> sequence_ ms
  let rec mapM f = function
    | []    -> return []
    | x::xs -> f x >>= fun x' -> mapM f xs >>= fun xs' -> return (x'::xs')
  let rec mapM_ f = function
    | []    -> return ()
    | x::xs -> f x >>= fun _ -> mapM_ f xs
  let rec foldM f z = function
    | []    -> return z
    | x::xs -> f z x >>= fun z' -> foldM f z' xs
end


(*
 * Concrete monads.
 *)

module Option = Monad_ext_make ( struct
  type 'a t = 'a option
  let return a = Some a
  let bind a f = match a with
    | None   -> None
    | Some x -> f x
end )

module type Or_error = sig
  type err
  type 'a or_error = Ok of 'a | Error of err
  val fail       : err -> 'a or_error
  val is_success : 'a or_error -> bool
  val is_error   : 'a or_error -> bool
  include Monad_ext with type 'a t = 'a or_error
end

module Or_error_make (M : sig type err end) :
  Or_error with type err = M.err =
struct
  type err = M.err
  type 'a or_error = Ok of 'a | Error of err
  let fail e   = Error e
  let is_success = function
    | Ok    _ -> true
    | Error _ -> false
  let is_error = function
    | Ok    _ -> false
    | Error _ -> true
  module Monad_impl = Monad_ext_make (struct
    type 'a t = 'a or_error
    let return a = Ok a
    let bind a f = match a with
      | Ok x    -> f x
      | Error e -> Error e
  end)
  include Monad_impl
end

module Or_string_error =
  Or_error_make (struct type err = string end)

