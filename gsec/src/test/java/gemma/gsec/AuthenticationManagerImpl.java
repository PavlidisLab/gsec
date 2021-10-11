package gemma.gsec;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class AuthenticationManagerImpl implements AuthenticationProvider {

    @Override
    public Authentication authenticate( Authentication authentication ) throws AuthenticationException {
        return null;
    }

    @Override
    public boolean supports( Class<?> aClass ) {
        return false;
    }
}
