importClass(Packages.com.ibm.security.access.policy.decision.Decision);
importClass(Packages.com.ibm.security.access.policy.decision.RedirectChallengeDecisionHandler);
importPackage(Packages.com.tivoli.am.fim.trustserver.sts.utilities);
/*Pre-requisite steps
1) We are using the username password authentication mechanism. Hence Advanced Access Control has to be activated and run isamcfg or isam aac config. The junction used for isamcfg is /mga.
2) We modify the AuthSvcCredential mapping rule to add an attribute called authenticationTime.
Example
stsuuAttrs.setAttribute(new Attribute("authenticationTime", null, (new Date()).getTime()));
3) Since we are using the username password authentication mechanism, remove the isam_oauth_anyauth acl from the /mga/sps/auth endpoint and attach an isam_oauth_unauth acl.(Assuming /mga is the junction created using the OAuth OIDC configuration)
4) Change the <ServerIP> to the IP address of the reverse proxy that will perform the username password authentication.

*/
var prompt_login = false;
var protocolContext = context.getProtocolContext();
//Checking if prompt is requested by retrieveing the authentication context.
var promptVal = protocolContext.getAuthenticationRequest().getAuthenticationContext().getPrompt();
if (promptVal != null) {
	prompt_login = true;
}
//Function used to call username password authentication mechanism
function getRedirectToAuthSvc() {
	var handler = new RedirectChallengeDecisionHandler();
	IDMappingExtUtils.traceString("rediect to authSvc");
	handler.setRedirectUri("/eai/web/v1/auth/login");
	IDMappingExtUtils.traceString("returning challenge");
	return handler;
}

if (prompt_login) {
	context.setDecision((function () {
		var request = context.getRequest();

		var user = context.getUser();
		if (user == null) {
			IDMappingExtUtils.traceString("User isnt authenticated");
			return Decision.challenge(getRedirectToAuthSvc());
		} else {
			// The current HTTP request contains authentication request.
			IDMappingExtUtils.traceString("Currently authenticated user: " + user);
			var responseType = request.getParameter("response_type");
			if (responseType == null) {
			} else {
				// User is authenticated.
				IDMappingExtUtils.traceString("Prompt is: " + promptVal);
				if (promptVal != null && promptVal.contains("login")) {
					return Decision.challenge(getRedirectToAuthSvc());
				} else {
					IDMappingExtUtils.traceString("Allowed");
					return Decision.allow();
				}
			}
		}

		IDMappingExtUtils.traceString("Allowed");
		return Decision.allow();
	})());
}
else {
	//If neither promot or max_age is requested, we retrieve user context
	context.setDecision((function () {
		var user = context.getUser();
		var auth_time;
		IDMappingExtUtils.traceString("user  :" + user);//Authenticate using username password mechanism if there is no user session
		if (user == null) {
			IDMappingExtUtils.traceString("User Session is unavailable");
			return Decision.challenge(getRedirectToAuthSvc());
		}
		else {
			return Decision.allow();
		}
	})());
}
