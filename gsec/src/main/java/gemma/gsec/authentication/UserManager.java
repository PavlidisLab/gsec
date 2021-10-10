/*
 * The Gemma_sec1 project
 *
 * Copyright (c) 2009 University of British Columbia
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package gemma.gsec.authentication;

import java.util.Collection;

import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.GroupManager;
import org.springframework.security.provisioning.UserDetailsManager;

import gemma.gsec.model.User;
import gemma.gsec.model.UserGroup;

/**
 * @author paul
 * @version $Id: UserManager.java,v 1.15 2013/09/22 18:50:43 paul Exp $
 */
public interface UserManager extends UserDetailsManager, GroupManager {

    /**
     * @param email
     * @param username
     * @param newPassword - encoded
     * @return the confirmation token they will need to use.
     */
    String changePasswordForUser( String email, String username, String newPassword );

    /**
     * @return list of all available usernames.
     */
    Collection<String> findAllUsers();

    /**
     * @param emailAddress
     * @return
     */
    User findbyEmail( String emailAddress );

    /**
     * @param emailAddress
     * @return
     */
    User findByEmail( String emailAddress );

    /**
     * Need a passthrough method to userService else we get a circular dependancy issue at runtime startup.
     *
     * @param userName
     * @return
     */
    User findByUserName( String userName ) throws UsernameNotFoundException;

    /**
     * Need a passthrough method to userService else we get a circular dependancy issue at runtime startup.
     *
     * @param name
     * @return
     */
    UserGroup findGroupByName( String name );

    /**
     * @param username
     * @return names of groups the user is in.
     */
    Collection<String> findGroupsForUser( String username ) throws UsernameNotFoundException;

    /**
     * Generate a token that can be used to check if the user's email is valid.
     *
     * @param username
     * @return
     */
    String generateSignupToken( String username ) throws UsernameNotFoundException;

    /**
     * @return the current user or null if the user is anonymous.
     */
    User getCurrentUser();

    /**
     * Returns a String username (the principal).
     *
     * @return
     */
    String getCurrentUsername();

    /**
     * @return the prefix use on roles (groups, actually) e.g. "GROUP_"
     */
    String getRolePrefix();

    /**
     * @param name
     * @return
     */
    boolean groupExists( String name );

    /**
     * Need a passthrough method to userService else we get a circular dependency issue at runtime startup.
     *
     * @return
     */
    <T extends User> Collection<T> loadAll();

    boolean loggedIn();

    /**
     * Sign in the user identified
     *
     * @param userName
     * @param password
     */
    void reauthenticate( String userName, String password );

    /**
     * @param emailAddress
     * @return
     */
    boolean userWithEmailExists( String emailAddress );

    /**
     * Validate the token.
     *
     * @param username
     * @param key
     * @return true if okay, false otherwise
     */
    boolean validateSignupToken( String username, String key );
}