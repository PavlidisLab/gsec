package gemma.gsec;

import gemma.gsec.authentication.UserManager;
import gemma.gsec.model.User;
import gemma.gsec.model.UserGroup;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;

@Component
public class UserManagerImpl implements UserManager {

    @Override
    public String changePasswordForUser( String email, String username, String newPassword ) {
        return null;
    }

    @Override
    public Collection<String> findAllUsers() {
        return null;
    }

    @Override
    public User findbyEmail( String emailAddress ) {
        return null;
    }

    @Override
    public User findByEmail( String emailAddress ) {
        return null;
    }

    @Override
    public User findByUserName( String userName ) throws UsernameNotFoundException {
        return null;
    }

    @Override
    public UserGroup findGroupByName( String name ) {
        return null;
    }

    @Override
    public Collection<String> findGroupsForUser( String username ) throws UsernameNotFoundException {
        return null;
    }

    @Override
    public String generateSignupToken( String username ) throws UsernameNotFoundException {
        return null;
    }

    @Override
    public User getCurrentUser() {
        return null;
    }

    @Override
    public String getCurrentUsername() {
        return null;
    }

    @Override
    public String getRolePrefix() {
        return null;
    }

    @Override
    public boolean groupExists( String name ) {
        return false;
    }

    @Override
    public <T extends User> Collection<T> loadAll() {
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
    public List<String> findAllGroups() {
        return null;
    }

    @Override
    public List<String> findUsersInGroup( String s ) {
        return null;
    }

    @Override
    public void createGroup( String s, List<GrantedAuthority> list ) {

    }

    @Override
    public void deleteGroup( String s ) {

    }

    @Override
    public void renameGroup( String s, String s1 ) {

    }

    @Override
    public void addUserToGroup( String s, String s1 ) {

    }

    @Override
    public void removeUserFromGroup( String s, String s1 ) {

    }

    @Override
    public List<GrantedAuthority> findGroupAuthorities( String s ) {
        return null;
    }

    @Override
    public void addGroupAuthority( String s, GrantedAuthority grantedAuthority ) {

    }

    @Override
    public void removeGroupAuthority( String s, GrantedAuthority grantedAuthority ) {

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
        return null;
    }
}
