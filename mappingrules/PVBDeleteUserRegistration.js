importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importClass(Packages.com.tivoli.am.fim.fido.mediation.FIDO2RegistrationHelper);
importClass(Packages.com.ibm.security.access.user.UserLookupHelper);
importMappingRule("PVBUtils");

const RULE_NAME="PVCB: INFOMAP: DeleteUserRegistration";
var serverName = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:header", "iv_server_name");
var POLICY_NAME = RULE_NAME+" : ServerName["+serverName+"] ";

/*
    Error Messages 
    PVBIMDUG000: System Error occurred, Please contact system admin.
    PVBIMDUG001: Unauthorized to call this API, User must be authenticated.
    PVBIMDUG002: Supplied username is invalid or empty, username must be 20 characters and alphanumeric
    PVBIMDUG003: Supplied username could not be found in ISVD registry, Please check username
*/

/* It is assumed that user is authenticated by the RP and ACL should be defined to restrict only admin 
user acesss to this API */
var authUser  = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username");
var pvbUserID = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "pvb-user-id");
var credentialID = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "credential-id");
var relyingPartyID = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "relying-party-id");
logMsg("INFO","Authenticated User "+authUser+", pvbUserID "+pvbUserID);
var registrationBeforeDeletion = 0;
var registerationAfterDeletion = 0;
var error = {};

try{
    if(authUser!=null){// User must be authenticated to call this API 
        if(isAuthorizedForTokenManagement(authUser)){
            var validUser = validateUsername(pvbUserID);
            if(validUser.isValid){
                logMsg("INFO"," Start method to get Access Tokens for User "+pvbUserID);
                var userAttributes = searchUser(pvbUserID);
                if(userAttributes!=null){
                    
                    var registrationHelper = new FIDO2RegistrationHelper();
                    var registrations = registrationHelper.getRegistrationsByUsername(pvbUserID); // Returns array of active FIDO2 registrations 
                    if(registrations!=null){
                        logMsg("INFO"," Active FIDO2 registrations : " + registrations.length);
                        registrationBeforeDeletion = registrations.length;

                        //Remove the registration entry - CredentialID
                        logMsg("INFO", "Credential ID : " + credentialID);
                        var registrationDelete = registrationHelper.removeRegistration​(relyingPartyID, credentialID);
                        
                        // Registration count - after deletion
                        registrations = registrationHelper.getRegistrationsByUsername(pvbUserID);
                        registerationAfterDeletion = registrations!=null ? registrations.length : 0 ;

                        logMsg("INFO",""+registrationBeforeDeletion+" registrations found for user and "+credentialID+" has been deleted ");
                        logMsg("INFO","Registrations after deleting CredentialID : "+registerationAfterDeletion);
                    }else{
                        logMsg("INFO"," Active FIDO2 Registrations : "+0);
                    }
                }else{
                    error.message = "User "+pvbUserID+" not found";
                    error.code = "PVBIMDUG003";
                    error.responseCode = 404;
                }
                
            }else{
                error.message = validUser.message;
                error.code = "PVBIMDUG002";
                error.responseCode = 500;
            }
        }else{
            error.message = "User "+authUser+" is not authorized to access this API";
            error.code = "PVBIMGUG001";
            error.responseCode = 401;
        }
        
    }else{
        error.message = "User must be authenticated to access this API";
        error.code = "PVBIMDUG001";
        error.responseCode = 401;
    }
}catch(e){
    error.message = "Unexpected error "+ e;
    error.code = "PVBIMDUG000";
    error.responseCode = 500;
}

if(error.message==null){
    page.setValue("/authsvc/authenticator/pvb/deleteuserregistration.html");
    var message = {};
    message.registrationBeforeDeletion = registrationBeforeDeletion;
    message.registerationAfterDeletion = registerationAfterDeletion;
    message.username = pvbUserID;
    logMsg("INFO","Returning Registrations "+JSON.stringify(message));
    macros.put("@MESSAGE@", JSON.stringify(message));
}else{
    logMsg("ERROR",""+ JSON.stringify(error));
    macros.put("@ERROR_MESSAGE@", JSON.stringify(error));
    page.setValue("/authsvc/authenticator/pvb/error.html");
}
success.setValue(false);
