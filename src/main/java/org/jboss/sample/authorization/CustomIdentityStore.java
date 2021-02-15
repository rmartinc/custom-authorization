package org.jboss.sample.authorization;

import javax.enterprise.context.RequestScoped;

import java.util.Arrays;
import java.util.HashSet;
import javax.security.enterprise.CallerPrincipal;
import javax.security.enterprise.credential.Credential;
import javax.security.enterprise.credential.UsernamePasswordCredential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import static javax.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;
import static javax.security.enterprise.identitystore.CredentialValidationResult.NOT_VALIDATED_RESULT;
import javax.security.enterprise.identitystore.IdentityStore;

@RequestScoped
public class CustomIdentityStore implements IdentityStore {
    
    public CredentialValidationResult validate(Credential credential) {
        if (credential instanceof UsernamePasswordCredential) {
            return validate((UsernamePasswordCredential) credential);
        }

        return NOT_VALIDATED_RESULT;
    }
    
    public CredentialValidationResult validate(UsernamePasswordCredential usernamePasswordCredential) {
        
        System.out.println("IdentityStore: validating user...");
        if (usernamePasswordCredential.getCaller().equals("test") && 
            usernamePasswordCredential.getPassword().compareTo("secret1")) {
            
            return new CredentialValidationResult(
                new CallerPrincipal("test"), 
                new HashSet<>(Arrays.asList("foo", "bar", "kaz"))
            );
        }
        
        return INVALID_RESULT;
    }
    
}
