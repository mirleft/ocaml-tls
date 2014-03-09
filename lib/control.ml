module type Monad = sig
  type 'a t
  val return : 'a -> 'a t
  val bind   : 'a t -> ('a -> 'b t) -> 'b t
end

module Monad (M : Monad) : sig
  val return : 'a -> 'a M.t
  val (>>=)  : 'a M.t -> ('a -> 'b M.t) -> 'b M.t
  val map    : ('a -> 'b) -> 'a M.t -> 'b M.t
  val sequence  : 'a M.t list -> 'a list M.t
  val sequence_ : 'a M.t list -> unit M.t
  val mapM      : ('a -> 'b M.t) -> 'a list -> 'b list M.t
  val mapM_     : ('a -> 'b M.t) -> 'a list -> unit M.t
  val foldM     : ('a -> 'b -> 'a M.t) -> 'a -> 'b list -> 'a M.t
end
  =
struct
  type 'a t = 'a M.t
  let return = M.return
  let (>>=)  = M.bind
  let map f a = a >>= fun x -> return (f x)
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

module Option = Monad ( struct
  type 'a t = 'a option
  let return a = Some a
  let bind a f = match a with
    | None   -> None
    | Some x -> f x
end )

module Or_error_make (M : sig type err end) = struct
  type 'a or_error = Ok of 'a | Error of M.err
  let fail e   = Error e
  let is_success = function
    | Ok    _ -> true
    | Error _ -> false
  let is_error = function
    | Ok    _ -> false
    | Error _ -> true
  module Monad_impl = Monad (struct
    type 'a t = 'a or_error
    let return a = Ok a
    let bind a f = match a with
      | Ok x    -> f x
      | Error e -> Error e
  end)
  include Monad_impl
end

module Or_string_error = Or_error_make (struct type err = string end)

