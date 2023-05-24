# Role-based Access Control (RBAC)
# --------------------------------
#
# This example defines an RBAC model for a sample application created to demo authentication and 
# authorization with proposed common auth service. The policy controls triggering of API endpoints 
# by a user according to the roles assigned to them. In this classic Role-based Access Control model
# users are assigned to roles and roles are granted the ability to perform some action(s) on 
# some type of resource.

package app.tenant1.ldc.rbac

import future.keywords.contains
import future.keywords.if
import future.keywords.in
import data.tenant1.ldc.rbac.api_list
import input

# By default, deny requests.
default allow := false

# Allow the action if the user is granted permission to perform the action.
allow if {
	api := api_list[input.url]
	api.method == input.method
	count(common_roles) > 0
}

common_roles contains role if {
	some role in api_list[input.url].roles
	role == token_claim_roles[_]
}

token_claim_roles := payload.realm_access.roles if {

    #key:=opa.runtime()["env"]["TOKEN_RSA_PUBLIC_KEY"]
    #token_signature:= concat("\n",["-----BEGIN PUBLIC KEY-----", key, "-----END PUBLIC KEY-----"])
	#io.jwt.verify_rs256(bearer_token, token_signature)
    [_, payload, _] := io.jwt.decode(bearer_token)
	#[_, _, payload] := io.jwt.decode_verify(bearer_token, {"cert":token_signature, "aud": "https://xaas_solutions.hitachivanara.com"})
    
}

bearer_token := t if {
	# parses the header and extracts the Bearer token value. If no Bearer token is
	# provided, the `bearer_token` value is undefined.
	v := input.token
	startswith(v, "Bearer ")
	t := substring(v, count("Bearer "), -1)
}

