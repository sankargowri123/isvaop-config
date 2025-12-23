importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importClass(Packages.com.tivoli.am.fim.fido.mediation.FIDO2RegistrationHelper);
importMappingRule("BranchingHelper");
importMappingRule("PVBUtils");

// Copyright contributors to the IBM Security Verify Access AAC Mapping Rules project.
IDMappingExtUtils.traceString("Entry FIDO2PAIR Username Validation");

const RULE_NAME = "PVCB: INFOMAP: PVBPasskeyUserValidation";
var serverName = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:header", "iv_server_name");
var POLICY_NAME = RULE_NAME + " : ServerName[" + serverName + "] ";
var error = {};
var result = true;

//Validate UserID exists in SDS instance
var pvbUserID = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "username");
IDMappingExtUtils.traceString("Username from request: " + pvbUserID);
var userAttributes = searchUser(pvbUserID);
if (userAttributes == null) {
    error.message = "User " + pvbUserID + " not found in verify";
    error.code = "PVBIMGUG003";
    error.responseCode = 404;

    result = false;
    logMsg("ERROR", "" + JSON.stringify(error));
    macros.put("@ERROR_MESSAGE@", JSON.stringify(error));
    page.setValue("/authsvc/authenticator/pvb/error.html");
} else { // If user exists in verify
    var registrationHelper = new FIDO2RegistrationHelper();
    var registrations = registrationHelper.getRegistrationsByUsername(pvbUserID); // Returns array of active FIDO2 registrations 
    if (registrations != null & registrations.length != 0) {
        logMsg("INFO", " Active FIDO2 registrations : " + registrations.length);
    } else {
        error.message = "FIDO2 Registrations for User " + pvbUserID + " not found";
        error.code = "PVBIMGUG003";
        error.responseCode = 404;
    
        result = false;
        logMsg("ERROR", "" + JSON.stringify(error));
        macros.put("@ERROR_MESSAGE@", JSON.stringify(error));
        page.setValue("/authsvc/authenticator/pvb/error.html");
    }
}

IDMappingExtUtils.traceString("Exit FIDO2PAIR Username Validation");
success.setValue(result);