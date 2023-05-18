package gemma.gsec.authentication;

import gemma.gsec.AuthorityConstants;
import org.junit.Test;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;

import static org.junit.Assert.assertTrue;

public class AuthenticationTrustResolverImplTest {

    private final AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();

    @Test
    public void test() {
        assertTrue( authenticationTrustResolver.isAnonymous( new AnonymousAuthenticationToken( "1234", "anon", Collections.singleton( new SimpleGrantedAuthority( AuthorityConstants.IS_AUTHENTICATED_ANONYMOUSLY ) ) ) ) );
        assertTrue( authenticationTrustResolver.isAnonymous( new UsernamePasswordAuthenticationToken( "anonymousUser", "1234" ) ) );
    }
}