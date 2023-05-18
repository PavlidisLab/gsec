package gemma.gsec.authentication;

import gemma.gsec.AuthorityConstants;
import org.springframework.security.core.Authentication;

public class AuthenticationTrustResolverImpl extends org.springframework.security.authentication.AuthenticationTrustResolverImpl {

    @Override
    public boolean isAnonymous( Authentication authentication ) {
        return super.isAnonymous( authentication )
            || ( authentication != null && AuthorityConstants.ANONYMOUS_USER_NAME.equals( authentication.getPrincipal() ) );
    }
}
