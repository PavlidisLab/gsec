package gemma.gsec;

import gemma.gsec.authentication.UserDetailsManager;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Collection;
import java.util.Collections;

public class UserDetailsManagerImpl implements UserDetailsManager {

    @Override
    public String changePasswordForUser( String email, String username, String newPassword ) {
        return "1234";
    }

    @Override
    public Collection<String> findAllUsers() {
        return Collections.emptyList();
    }

    @Override
    public String generateSignupToken( String username ) throws UsernameNotFoundException {
        return "1234";
    }

    @Nullable
    @Override
    public String getCurrentUsername() {
        return null;
    }

    @Override
    public boolean loggedIn() {
        return false;
    }

    @Override
    public void reauthenticate( String userName, String password ) {

    }

    @Override
    public boolean userWithEmailExists( String emailAddress ) {
        return false;
    }

    @Override
    public boolean validateSignupToken( String username, String key ) {
        return false;
    }

    @Override
    public void createUser( UserDetails userDetails ) {

    }

    @Override
    public void updateUser( UserDetails userDetails ) {

    }

    @Override
    public void deleteUser( String s ) {

    }

    @Override
    public void changePassword( String s, String s1 ) {

    }

    @Override
    public boolean userExists( String s ) {
        return false;
    }

    @Override
    public UserDetails loadUserByUsername( String s ) throws UsernameNotFoundException {
        throw new UsernameNotFoundException( s );
    }
}
