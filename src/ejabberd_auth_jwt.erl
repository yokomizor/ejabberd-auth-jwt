%%%----------------------------------------------------------------------
%%% File    : ejabberd_auth_jwt.erl
%%% Author  : Rogerio da Silva Yokomizo <me@ro.ger.io>
%%% Purpose : Authentification via JWT token
%%% Created : 10 May 2018 by Rogerio da Silva Yokomizo <me@ro.ger.io>
%%%
%%%
%%% Copyright 2018 Rogerio da Silva Yokomizo
%%%
%%% Licensed under the Apache License, Version 2.0 (the "License");
%%% you may not use this file except in compliance with the License.
%%% You may obtain a copy of the License at
%%%
%%%     http://www.apache.org/licenses/LICENSE-2.0
%%%
%%% Unless required by applicable law or agreed to in writing, software
%%% distributed under the License is distributed on an "AS IS" BASIS,
%%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%% See the License for the specific language governing permissions and
%%% limitations under the License.
%%%----------------------------------------------------------------------

-module(ejabberd_auth_jwt).

-behaviour(gen_mod).

-author('me@ro.ger.io').

-export([check_password/4, depends/2, mod_options/1, mod_opt_type/1,
	 plain_password_required/1, reload/1, remove_user/2,
	 set_password/3, start/1, start/2, stop/1, store_type/1,
	 try_register/3, use_cache/1, user_exists/2]).

-record(jose_jwt, {fields = #{}  :: map()}).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

%%%----------------------------------------------------------------------
%%% API
%%%----------------------------------------------------------------------
start(_Host) -> ok.

start(_Host, _Opts) -> ok.

stop(_Host) -> ok.

reload(_Host) -> ok.

plain_password_required(_) -> true.

use_cache(_) -> false.

store_type(_) -> external.

check_password(User, AuthzId, Server, Password) ->
    if AuthzId /= <<>> andalso AuthzId /= User -> false;
       true -> check_password_jwt(User, Server, Password)
    end.

set_password(_User, _Server, _Password) ->
    {error, not_allowed}.

try_register(_User, _Server, _Password) ->
    {error, not_allowed}.

user_exists(_User, _Server) -> true.

remove_user(_User, _Server) -> {error, not_allowed}.

depends(_Host, _Opts) -> [].

mod_opt_type(strict_alg) -> fun iolist_to_binary/1;
mod_opt_type(user_claim) -> fun iolist_to_binary/1;
mod_opt_type(key) -> fun iolist_to_binary/1;
mod_opt_type(pem_file) -> fun iolist_to_binary/1;
mod_opt_type(_) ->
    [key, pem_file, user_claim, strict_alg].

mod_options(_) ->
    [{key, []},{pem_file, []}, {user_claim, []},{strict_alg, []}].


%%%----------------------------------------------------------------------
%%% Internal functions
%%%----------------------------------------------------------------------
check_password_jwt(User, Server, Fields)
    when is_map(Fields) ->
    UserClaim =
        gen_mod:get_module_opt(Server, ?MODULE, user_claim),
    case maps:find(UserClaim, Fields) of
      {ok, User} -> true;
      _ -> false
    end;
check_password_jwt(User, Server, Password) ->
    JWK = get_jwk(Server),
    Alg = gen_mod:get_module_opt(Server, ?MODULE, strict_alg),
    try verify_token(JWK, Alg, Password) of
      {true, #jose_jwt{fields = Fields}, _} ->
	  check_password_jwt(User, Server, Fields);
      _ ->
          false
    catch
      _:_ -> false
    end.

verify_token(JWK, <<"">>, Token) ->
    jose_jwt:verify(JWK, Token);
verify_token(JWK, Alg, Token) ->
    jose_jwt:verify_strict(JWK, [Alg], Token).

get_jwk(Server) ->
    case gen_mod:get_module_opt(Server, ?MODULE, pem_file)
        of
      <<"">> ->
          HS256Key = gen_mod:get_module_opt(Server, ?MODULE, key),
          HS256KeyBase64 = base64url:encode(HS256Key),
          #{<<"kty">> => <<"oct">>, <<"k">> => HS256KeyBase64};
      RSAKeyFile ->
          jose_jwk:from_pem_file(RSAKeyFile)
    end.

%%%----------------------------------------------------------------------
%%% Tests
%%%----------------------------------------------------------------------
-ifdef(TEST).
start_test() ->
    ?assertEqual(ok, start("")),
    ?assertEqual(ok, start("", "")).

stop_test() ->
    ?assertEqual(ok, stop("")).

reload_test() ->
    ?assertEqual(ok, reload("")).

plain_password_required_test() ->
    ?assert(plain_password_required("")).

use_cache_test() ->
    ?assertEqual(false, use_cache("")).

store_type_test() ->
    ?assertEqual(external, store_type("")).

set_password_test() ->
    ?assertEqual({error, not_allowed}, set_password("", "", "")).

try_register_test() ->
    ?assertEqual({error, not_allowed}, try_register("", "", "")).

user_exists_test() ->
    ?assert(user_exists("", "")).

remove_user_test() ->
    ?assertEqual({error, not_allowed}, remove_user("", "")).

depends_test() ->
    ?assertEqual([], depends("", "")).

mod_opt_type_test() ->
    StrictAlg = mod_opt_type(strict_alg),
    UserClaim = mod_opt_type(user_claim),
    Key = mod_opt_type(key),
    PemFile = mod_opt_type(pem_file),
    ?assertEqual(<<"TEST">>, StrictAlg("TEST")),
    ?assertEqual(<<"TEST">>, UserClaim("TEST")),
    ?assertEqual(<<"TEST">>, Key("TEST")),
    ?assertEqual(<<"TEST">>, PemFile("TEST")),
    ?assertEqual([key, pem_file, user_claim, strict_alg], mod_opt_type(unknown)).

mod_options_test() ->
    ?assertEqual([{key, []},{pem_file, []}, {user_claim, []},{strict_alg, []}], mod_options(unknown)).


verify_token_test() ->
    JWK = #{<<"kty">> => <<"oct">>, <<"k">> => <<"U0VDUkVU">>},
    ValidToken = <<"VALID">>,
    InvalidToken = <<"INVALID">>,
    ValidAlg = <<"VALID_ALG">>,
    InvalidAlg = <<"INVALID_ALG">>,
    meck:new(jose_jwt, [non_strict]),
    meck:expect(jose_jwt, verify, fun(_, Token) -> { Token =:= ValidToken, ok, ok } end),
    meck:expect(jose_jwt, verify_strict, fun(_, [Arg], Token) -> { Arg =:= ValidAlg andalso Token =:= ValidToken , ok, ok } end),
    { true, _, _ } = verify_token(JWK, <<"">>, ValidToken),
    { true, _, _ } = verify_token(JWK, ValidAlg, ValidToken),
    { false, _, _ } = verify_token(JWK, InvalidAlg, ValidToken),
    { false, _, _ } = verify_token(JWK, ValidAlg, InvalidToken).

get_jwk_test() ->
    Server = <<"Server">>,
    HS256Key = <<"SECRET">>,
    HS256KeyBase64 = <<"SECRET_BASE64">>,
    JWK = #{<<"kty">> => <<"oct">>, <<"k">> => HS256KeyBase64},
    meck:new(base64url, [non_strict]),
    meck:expect(base64url, encode, fun(Input) -> case Input =:= HS256Key of true -> HS256KeyBase64; _ -> <<"ANY_BASE64">> end end),
    meck:new(gen_mod, [non_strict]),
    meck:expect(gen_mod, get_module_opt, fun(_, _, Opt) -> case Opt of pem_file -> <<"">>; key -> HS256Key end end),
    ?assertEqual(JWK, get_jwk(Server)).

get_jwk_rsa_test() ->
    Server = <<"Server">>,
    PemFile = <<"PEM_FILE">>,
    JWK = #{<<"kty">> => <<"RSA">>, <<"k">> => <<"KEY">>},
    meck:new(jose_jwk, [non_strict]),
    meck:expect(jose_jwk, from_pem_file, fun(Input) -> case Input =:= PemFile of true -> JWK; _ -> <<"ANY_JWK">> end end),
    % meck:new(gen_mod, [non_strict]),
    meck:expect(gen_mod, get_module_opt, fun(_, _, pem_file) -> PemFile end),
    ?assertEqual(JWK, get_jwk(Server)).

check_password_jwt_is_map_test() ->
    ValidUser = <<"ValidUser">>,
    InvalidUser = <<"InvalidUser">>,
    Server = <<"Server">>,
    Fields = #{<<"sub">> => ValidUser},
    meck:expect(gen_mod, get_module_opt, fun(_, _, user_claim) -> <<"sub">> end),
    ?assert(check_password_jwt(ValidUser, Server, Fields)),
    ?assertNot(check_password_jwt(InvalidUser, Server, Fields)).

check_password_jwt_test() ->
    ValidUser = <<"ValidUser">>,
    InvalidUser = <<"InvalidUser">>,
    JWK = #{<<"kty">> => <<"oct">>, <<"k">> => <<"U0VDUkVU">>},
    ValidToken = <<"VALID">>,
    InvalidToken = <<"INVALID">>,
    ValidAlg = <<"VALID_ALG">>,
    InvalidAlg = <<"INVALID_ALG">>,
    Fields = #{<<"sub">> => ValidUser},
    PemFile = <<"PEM_FILE">>,
    Server = <<"Server">>,
    meck:expect(gen_mod, get_module_opt, fun(_, _, Opt) -> case Opt of
                                                               pem_file -> PemFile;
                                                               strict_alg -> ValidAlg;
                                                               user_claim -> <<"sub">>
                                                           end end),
    meck:expect(jose_jwk, from_pem_file, fun(Input) -> case Input =:= PemFile of true -> JWK; _ -> <<"ANY_JWK">> end end),
    meck:expect(jose_jwt, verify_strict, fun(_, [Arg], Token) -> { Arg =:= ValidAlg andalso Token =:= ValidToken, #jose_jwt{fields = Fields}, ok } end),
    ?assert(check_password_jwt(ValidUser, Server, ValidToken)),
    ?assertNot(check_password_jwt(ValidUser, Server, InvalidToken)),
    ?assert(check_password(ValidUser, <<>>, Server, ValidToken)).

-endif.

