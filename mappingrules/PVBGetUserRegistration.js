importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.OAuthMappingExtUtils);
importClass(Packages.com.ibm.security.access.user.UserLookupHelper);
importClass(Packages.com.tivoli.am.fim.fido.mediation.FIDO2RegistrationHelper);
importClass(Packages.com.ibm.security.access.server_connections.ServerConnectionFactory);
importClass(Packages.com.ibm.security.access.server_connections.LdapServerConnection)
importMappingRule("PVBUtils");


/*
    Error Messages 
    PVBIMGUG000: System Error occurred, Please contact system admin.
    PVBIMGUG001: Unauthorized to call this API, User must be authenticated.
    PVBIMGUG002: Supplied username is invalid or empty, username must be 20 characters and alphanumeric
    PVBIMGUG003: Supplied username could not be found in ISVD registry, Please check username
*/


const RULE_NAME="PVCB: INFOMAP: GetUserRegistration";
var serverName = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:header", "iv_server_name");
var POLICY_NAME = RULE_NAME+" : ServerName["+serverName+"] ";
var error = {};
var userRegistrations = [];

/* It is assumed that user is authenticated by the RP and ACL should be defined to restrict only admin 
    user acesss to this API */
var authUser  = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username");
var pvbUserID = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "pvb-user-id");

//authUser = "dummy";

logMsg("INFO","Authenticated User "+authUser+", pvbUserID "+pvbUserID);
try{
    if(authUser!=null ){// User must be authenticated to call this API 
        if(isAuthorizedForTokenManagement(authUser)){
            var validUser = validateUsername(pvbUserID);
            if(validUser.isValid){
                logMsg("INFO"," Start method to get FIDO2 registrations for User "+pvbUserID);
                var userAttributes = searchUser(pvbUserID);
                if(userAttributes!=null){
                    var registrationHelper = new FIDO2RegistrationHelper();
                    var registrations = registrationHelper.getRegistrationsByUsername(pvbUserID); // Returns array of active FIDO2 registrations 
                    if(registrations!=null){
                        logMsg("INFO"," Active FIDO2 registrations : " + registrations.length);
                        //registrations.forEach(fruit => {})
                        for (i=0;i<registrations.length;i++){
                            var registrationsInDB = registrations[i];
                            userRegistrations.push(JSON.parse(registrationsInDB));
                            //macros.put("@TOKEN_ID@", token.getId());
                        }
                    }else{
                        logMsg("INFO"," Active FIDO2 Registrations : "+0);
                    }
                    
                }else{
                    error.message = "User "+pvbUserID+" not found";
                    error.code = "PVBIMGUG003";
                    error.responseCode = 404;
                }
            }else{
                error.message = validUser.message;
                error.code = "PVBIMGUG002";
                error.responseCode = 500;
            }
        }else{
            error.message = "User "+authUser+" is not authorized to access this API";
            error.code = "PVBIMGUG001";
            error.responseCode = 401;
        }
    }else{
        error.message = "User must be authenticated to access this API";
        error.code = "PVBIMGUG001";
        error.responseCode = 401;
    }
}catch (e){
    error.message = "Unexpected error "+ e;
    error.code = "PVBIMGUG000";
    error.responseCode = 500;
}

if(error.message==null){
    page.setValue("/authsvc/authenticator/pvb/getuserregistrations.html");
    logMsg("INFO","Returning FIDO2 registrations : "+JSON.stringify(userRegistrations));
    macros.put("@FIDO2_REGISTRATIONS@", JSON.stringify(userRegistrations));
}else{
    logMsg("ERROR",""+ JSON.stringify(error));
    macros.put("@ERROR_MESSAGE@", JSON.stringify(error));
    page.setValue("/authsvc/authenticator/pvb/error.html");
}
success.setValue(false);
