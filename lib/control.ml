module type Monad = sig
  type 'a t
  val return : 'a -> 'a t
  val bind   : 'a t -> ('a -> 'b t) -> 'b t
end

module Monad (M : Monad) : sig
  type 'a t
  val return : 'a -> 'a t
  val (>>=)  : 'a t -> ('a -> 'b t) -> 'b t
  val sequence  : 'a t list -> 'a list t
  val sequence_ : 'a t list -> unit t
  val mapM      : ('a -> 'b t) -> 'a list -> 'b list t
  val mapM_     : ('a -> 'b t) -> 'a list -> unit t
end with type 'a t = 'a M.t
  =
struct
  type 'a t = 'a M.t
  let return = M.return
  let (>>=)  = M.bind
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
end

module Option = Monad ( struct
  type 'a t = 'a option
  let return a = Some a
  let bind a f = match a with
    | None   -> None
    | Some x -> f x
end )

module Or_error_make (M : sig type err end) = struct
  type 'a t = Ok of 'a | Error of M.err
  let return a = Ok a
  let bind a f = match a with
    | Ok x    -> f x
    | Error e -> Error e
end

module Or_string_error = Or_error_make (struct type err = string end)

