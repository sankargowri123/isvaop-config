importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importPackage(Packages.com.ibm.security.access.ldap.utils)
importPackage(Packages.javax.naming.directory);
importMappingRule("PVBConst");

let logLevelsAllowed ="ERROR WARN INFO DEBUG";// Change this to allow different log levels

const USER_BASE_DN = "ou=retail,ou=customers,DC=PVB,DC=VN";
const SVD_SERVER_CONN = "CIAMUsers";

/* Search user in  ou=retail,ou=customers,DC=PVB,DC=VN OU based on username */
function searchUser(username){
    var resultAttrs = null;
    var ldapCtx = new AttributeUtil();
    ldapCtx.init(SVD_SERVER_CONN, USER_BASE_DN);
    var searchFilter = "(uid="+username+")";
    var ldapResult = ldapCtx.search(USER_BASE_DN,searchFilter);
    var result = ldapResult.getNamingEnumeration();
    if(result !=null && result.hasMore()){
      var resultEntry = result.next();
      resultAttrs = resultEntry.getAttributes();
      logMsg("DEBUG","searchUser(): User "+username+" found in "+SVD_SERVER_CONN+" user registry");
    }else{
      logMsg("INFO","searchUser(): User "+username+" not found in "+SVD_SERVER_CONN+" user registry");
    }
    return resultAttrs;
}

/*Check if the username is included in TOKEN_MANAGEMENT_ALLOWED_USERS */
function isAuthorizedForTokenManagement(username){
  var isAuthorized = false;
  for(i=0;i<TOKEN_MANAGEMENT_ALLOWED_USERS.length;i++){
    if(username==TOKEN_MANAGEMENT_ALLOWED_USERS[i]){
      isAuthorized = true;
      break;
    }
  }
  return isAuthorized;
}

function validateUsername(username) {
    // Define the regex for alphanumeric characters only
    const regex = /^[a-zA-Z0-9]+$/;
  
    // Check if the username meets both conditions
    if (username !=null && username.length > 20) {
      return { isValid: false, message: "Username must not exceed 20 characters." };
    }
    if (!regex.test(username)) {
      return { isValid: false, message: "Username must contain only alphanumeric characters." };
    }
    return { isValid: true, message: "Username is valid." };
}

//Use this function to log message
function logMsg(type, msg, policyType){
	if(logLevelsAllowed.indexOf(type)!=-1){
		var sessionID = IDMappingExtUtils.getSPSSessionID();
		var serverName = "";
		var userName = "unauthenticated";
		if(policyType=="IM"){
		    serverName = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:header", "iv_server_name");
		    userName = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username");;
		    userName = (userName!=null)?userName:"unauthenticated";
        }
        if(policyType=="AP"){
             var user = context.getUser();
             userName = (user!=null && user!="NOT_FOUND")? user.getUsername(): "unauthenticated";
             var request = context.getRequest();
             serverName = (request!=null)?request.getHeader("iv_server_name"):"";
        }
		IDMappingExtUtils.traceString(serverName+" "+sessionID+" "+userName+" "+POLICY_NAME+" "+type+" : "+msg);
	}
}

// use this function to throw expection
function throwException(msg){
	var sessionID = IDMappingExtUtils.getSPSSessionID();
	var expceptionMsg = POLICY_NAME+ " : "+sessionID+" : "+msg;
	IDMappingExtUtils.traceString(POLICY_NAME+" : "+sessionID+": ERROR : "+msg);
	IDMappingExtUtils.throwSTSException(POLICY_NAME+" : "+sessionID+" : "+msg);
}
