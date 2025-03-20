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

import gemma.gsec.model.GroupAuthority;
import gemma.gsec.model.User;
import gemma.gsec.model.UserGroup;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;

import javax.annotation.Nullable;
import java.util.Collection;

/**
 * @author paul
 * @version $Id: UserService.java,v 1.6 2014/06/17 19:20:47 paul Exp $
 */
@SuppressWarnings("unused")
public interface UserService {

    @Secured({ "GROUP_USER", "ACL_SECURABLE_EDIT" })
    void addGroupAuthority( UserGroup group, String authority );

    @Secured({ "GROUP_USER", "ACL_SECURABLE_EDIT" /* this applies to the first arg only! - should use an expression */ })
    void addUserToGroup( UserGroup group, User user );

    @Secured({ "GROUP_ADMIN" })
    User create( User user ) throws UserExistsException;

    @Secured({ "GROUP_USER" })
    UserGroup create( UserGroup group );

    /**
     * Remove a user from the persistent store.
     */
    @Secured({ "GROUP_ADMIN" })
    void delete( User user );

    /**
     * Remove a group from the persistent store
     */
    @Secured({ "GROUP_USER", "ACL_SECURABLE_EDIT" })
    void delete( UserGroup group );

    @Nullable
    @Secured({ "GROUP_USER", "AFTER_ACL_READ" })
    User findByEmail( String email );

    /**
     * @return user or null if they don't exist.
     */
    @Nullable
    User findByUserName( String userName ); // don't secure,

    // to allow login

    @Secured({ "GROUP_USER", "AFTER_ACL_READ" })
    UserGroup findGroupByName( String name );

    @Secured({ "GROUP_USER", "AFTER_ACL_COLLECTION_READ" })
    Collection<UserGroup> findGroupsForUser( User user );

    @Secured("GROUP_USER")
    boolean groupExists( String name );

    /**
     * A list of groups available to the current user (will be security-filtered)...might need to allow anonymous.
     */
    @Secured({ "GROUP_USER", "AFTER_ACL_COLLECTION_READ" })
    Collection<UserGroup> listAvailableGroups();

    @Secured({ "GROUP_USER", "AFTER_ACL_READ" })
    User load( Long id );

    /**
     * Retrieves a list of users
     */
    @Secured({ "GROUP_ADMIN" })
    Collection<User> loadAll();

    Collection<GroupAuthority> loadGroupAuthorities( User u ); // must not be secured to allow login...

    /**
     * Remove an authority from a group. Would rarely be used.
     */
    @Secured({ "GROUP_ADMIN" })
    void removeGroupAuthority( UserGroup group, String authority );

    @PreAuthorize("hasPermission(#group, 'write') or hasPermission(#group, 'administration')")
    void removeUserFromGroup( User user, UserGroup group );

    @Secured({ "GROUP_USER", "ACL_SECURABLE_EDIT" })
    void update( User user );

    @Secured({ "GROUP_USER", "ACL_SECURABLE_EDIT" })
    void update( UserGroup group );
}
