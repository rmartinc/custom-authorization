package org.jboss.sample.authorization;

import static java.lang.System.out;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.security.enterprise.AuthenticationException;
import javax.security.enterprise.AuthenticationStatus;
import javax.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import javax.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import javax.security.enterprise.credential.UsernamePasswordCredential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import static javax.security.enterprise.identitystore.CredentialValidationResult.Status.VALID;
import javax.security.enterprise.identitystore.IdentityStore;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RequestScoped
public class CustomAuthenticationMechanism implements HttpAuthenticationMechanism {
    
    @Inject
    private IdentityStore identityStore;

    @Override
    public AuthenticationStatus validateRequest(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext) throws AuthenticationException {

        out.println("validateRequest called. Authentication mandatory: " + httpMessageContext.isProtected());
        
        if (request.getParameter("name") != null && request.getParameter("password") != null) {

            CredentialValidationResult result = identityStore.validate(
                new UsernamePasswordCredential(request.getParameter("name"), request.getParameter("password")));

            if (result.getStatus() == VALID) {
                return httpMessageContext.notifyContainerAboutLogin(
                    result.getCallerPrincipal(), result.getCallerGroups());
            } else {
                throw new AuthenticationException("Login failed");
            }
        } 

        return httpMessageContext.doNothing();
    }
    
}
