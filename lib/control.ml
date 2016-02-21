open Result

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
  val bind   : 'a t -> ('a -> 'b t) -> 'b t
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
  let bind   = M.bind
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
  type 'a t
  val fail       : err -> 'a t
  val is_success : 'a t -> bool
  val is_error   : 'a t -> bool
  include Monad_ext with type 'a t := 'a t
  val guard      : bool -> err -> unit t
  val or_else    : 'a t -> 'a -> 'a
  val or_else_f  : 'a t -> ('b -> 'a) -> 'b -> 'a
end

module Or_error_make (M : sig type err end) :
  Or_error with type err = M.err and type 'a t = ('a, M.err) result =
struct
  type err = M.err
  type 'a t = ('a, err) result
  let fail e   = Error e
  let is_success = function
    | Ok    _ -> true
    | Error _ -> false
  let is_error = function
    | Ok    _ -> false
    | Error _ -> true
  include (
    Monad_ext_make ( struct
      type nonrec 'a t = 'a t
      let return a = Ok a
      let bind a f = match a with
        | Ok x    -> f x
        | Error e -> Error e
    end ) : Monad_ext with type 'a t := 'a t)
  let guard pred err = if pred then return () else fail err
  let or_else m a = match m with Ok x -> x | _ -> a
  let or_else_f m f b = match m with Ok x -> x | _ -> f b
end


(** Lazy streams for reflecting the effect of ambiguous operator.

    NOTE: This is for interacting with alternatives; computing in the stream
    domain is (asymptotically) worse than doing the same in the amb domain!
 *)
module Stream = struct
  let force = Lazy.force
  type 'a t = Nil | Cons of 'a * 'a t Lazy.t
  let nil = Nil
  let cons a s = Cons (a, s)
  let lnil = lazy Nil
  let sg a = Cons (a, lnil)
  let uncons = function Nil -> None | Cons (x, xs) -> Some (x, xs)
  let rec map f = function
    | Cons (x, xs) -> Cons (f x, lazy (force xs |> map f))
    | Nil          -> Nil
  let rec fold f acc = function
    | Cons (x, xs) -> force xs |> fold f (f acc x) | Nil -> acc
  let rec iter f = function
    | Cons (x, xs) -> f x; force xs |> iter f | Nil -> ()
  let rec append xs lys = match xs with
    | Cons (x, xs) -> Cons (x, lazy (append (force xs) lys))
    | Nil          -> force lys
  let rec (>>=) a fb = match a with
    | Nil          -> Nil
    | Cons (x, xs) -> append (fb x) (lazy (force xs >>= fb))
end

module type Amb = sig

  type 'err effect
  type ('a, 'err) t = ('a, 'err effect) Eff.t

  include S.Monad2 with type ('a, 'e) t := ('a, 'e) t

  val refl  : ('a, 'e) t -> ('a, 'e) result Stream.t
  val refl1 : ('a, 'e) t -> ('a, 'e) result

  val fail  : 'e -> ('a, 'e) t
  val guard : bool -> 'e -> (unit, 'e) t
  val catch : ('a, 'e1) t -> ('e1 -> ('a, 'e2) t) -> ('a, 'e2) t
  val map_err : ('e1 -> 'e2) -> ('a, 'e1) t -> ('a, 'e2) t

  val amb : 'a list -> ('a, 'e) t

  module Operators : sig
    include S.Monad2 with type ('a, 'e) t := ('a, 'e) t
    val fail : 'e -> ('a, 'e) t
    val guard : bool -> 'e -> (unit, 'e) t
  end

  val foldM : ('a -> 'b -> ('a, 'e) t) -> 'a -> 'b list -> ('a, 'e) t
end

(** Hand-fused Amb + Error (for simplicity and performance) over the
   "freer monad." Error-parametric. *)
module Amb : Amb = struct

  open Eff

  type (_, _) req = 
    | Amb : 'a list -> ('a, 'e) req
    | Err : 'e -> ('a, 'e) req
  module Req = Higher.Newtype2 (struct type ('a, 'b) t = ('a, 'b) req end)

  type 'err effect = ('err, Req.t) Higher.app
  type ('a, 'err) t   = ('a, 'err effect) Eff.t

  let fail err = Req.inj (Err err) |> req
  let amb  xs  = Req.inj (Amb xs) |> req

  let return_unit = Pure ()

  let guard p err = if p then return_unit else fail err

  let rec catch t f = match t with
    | Pure a          -> Pure a
    | Impure (req, k) ->
        match Req.prj req with
        | Err err -> f err
        | Amb xs  -> Impure (Req.inj (Amb xs), after k (fun m -> catch m f))

  let map_err f t = catch t (fun e -> fail (f e))

  let refl xs =
    let rec go : type a e. (a, e) t -> (a, e) result Stream.t Lazy.t -> (a, e) result Stream.t =
      fun t rest -> match t with
      | Pure a          -> Stream.cons (Ok a) rest
      | Impure (req, k) ->
          match Req.prj req with
          | Err err -> Stream.cons (Error err) rest
          | Amb xs  ->
              let rec enum = function
                | []    -> Lazy.force rest
                | x::xs -> go (app k x) (lazy (enum xs)) in
              enum xs in
    go xs Stream.lnil

  (** [refl1 x] is an *assertion* that [x] is non-empty. Its value is the
      liftmost branch in [x]. *)
  let refl1 xs =
    match Stream.uncons (refl xs) with
    | Some (h, _) -> h
    | None        -> failwith "Static invariant broken: empty choice"

  module Operators = struct

    let ((>>=), (>|=), return) = Eff.((>>=), (>|=), return)
    let fail  = fail
    let guard = guard
  end

  include Operators

  (** We can get higher-kinded polymorphism, but we cannot be kind-polymorphic.
      Bits of [Monad_ext] actually used in the code. *)

  let rec foldM f z = function
    | []    -> return z
    | x::xs -> f z x >>= fun z' -> foldM f z' xs
end
