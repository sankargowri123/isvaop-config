importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
IDMappingExtUtils.traceString("Starting Access Policy JS");

var use_external_consent = false;

if (context.getRequest().getHeader("x-origin-ip") == "1.2.3.4") {
    /**
     * Here is an example of doing deny page response
     */
    var handler = new HtmlPageDenyDecisionHandler();
    handler.setMacro("@ERROR_CODE@", "access_denied");
    handler.setMacro("@ERROR_DESCRIPTION@", "Request coming from forbidden IP address.");
    handler.setPageId("user_error.html");
    context.setDecision(Decision.deny(handler));
} else {
    /**
     * Using external consent:
     * In the access policy javascript, you can response with a page challenge which
     * show a consent page; or it is possible also to redirect to external consent system.
     * After the consent is collected, the information of consented scope can be passed on
     * by calling 'setConsentDecision()'
     */
    if (use_external_consent) {
        var extScopes = ["openid", "email"];
        context.getProtocolContext().setConsentDecision(extScopes);
    }
    context.setDecision(Decision.allow());
}