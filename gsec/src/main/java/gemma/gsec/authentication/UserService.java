/*
 * The Gemma project.
 *
 * Copyright (c) 2006-2007 University of British Columbia
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

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;

import gemma.gsec.model.GroupAuthority;
import gemma.gsec.model.User;
import gemma.gsec.model.UserGroup;

/**
 * @version $Id: UserService.java,v 1.6 2014/06/17 19:20:47 paul Exp $
 * @author paul
 */
public interface UserService {

    /**
     * @param group
     * @param authority
     */
    @Secured({ "GROUP_USER", "ACL_SECURABLE_EDIT" })
    void addGroupAuthority( UserGroup group, String authority );

    /**
     * @param user
     * @param group
     */
    @Secured({ "GROUP_USER", "ACL_SECURABLE_EDIT" /* this applies to the first arg only! - should use an expression */ })
    void addUserToGroup( UserGroup group, User user );

    /**
     * @param user
     * @return
     * @throws UserExistsException
     */
    @Secured({ "GROUP_ADMIN" })
    User create( User user ) throws UserExistsException;

    /**
     * @param group
     * @return
     */
    @Secured({ "GROUP_USER" })
    UserGroup create( UserGroup group );

    /**
     * Remove a user from the persistent store.
     *
     * @param user
     */
    @Secured({ "GROUP_ADMIN" })
    void delete( User user );

    /**
     * Remove a group from the persistent store
     *
     * @param group
     */
    @Secured({ "GROUP_USER", "ACL_SECURABLE_EDIT" })
    void delete( UserGroup group );

    /**
     *
     */
    @Secured({ "GROUP_USER", "AFTER_ACL_READ" })
    User findByEmail( java.lang.String email );

    /**
     * @param userName
     * @return user or null if they don't exist.
     */
    User findByUserName( String userName ); // don't secure,

    // to allow login

    /**
     * @param oldName
     * @return
     */
    @Secured({ "GROUP_USER", "AFTER_ACL_READ" })
    UserGroup findGroupByName( String name );

    /**
     * @param usernName
     * @return
     */
    @Secured({ "GROUP_USER", "AFTER_ACL_COLLECTION_READ" })
    Collection<UserGroup> findGroupsForUser( User user );

    @Secured("GROUP_USER")
    boolean groupExists( String name );

    /**
     * A list of groups available to the current user (will be security-filtered)...might need to allow anonymous.
     */
    @Secured({ "GROUP_USER", "AFTER_ACL_COLLECTION_READ" })
    Collection<UserGroup> listAvailableGroups();

    /**
     * @param id
     * @return
     */
    @Secured({ "GROUP_USER", "AFTER_ACL_READ" })
    User load( Long id );

    /**
     * Retrieves a list of users
     */
    @Secured({ "GROUP_ADMIN" })
    Collection<User> loadAll();

    /**
     * @param u
     * @return
     */
    Collection<GroupAuthority> loadGroupAuthorities( User u ); // must not be secured to allow login...

    /**
     * Remove an authority from a group. Would rarely be used.
     *
     * @param group
     * @param authority
     */
    @Secured({ "GROUP_ADMIN" })
    void removeGroupAuthority( UserGroup group, String authority );

    /**
     * @param user
     * @param group
     */
    @PreAuthorize("hasPermission(#group, 'write') or hasPermission(#group, 'administration')")
    void removeUserFromGroup( User user, UserGroup group );

    /**
     * @param user
     */
    @Secured({ "GROUP_USER", "ACL_SECURABLE_EDIT" })
    void update( User user );

    /**
     * @param group
     */
    @Secured({ "GROUP_USER", "ACL_SECURABLE_EDIT" })
    void update( UserGroup group );
}
