/*
 * The Gemma project
 *
 * Copyright (c) 2012 University of British Columbia
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package gemma.gsec;

import gemma.gsec.acl.voter.AclEntryCollectionVoter;
import gemma.gsec.model.Securable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.AuthorizationServiceException;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.acls.model.Sid;

import java.util.Collection;
import java.util.Map;

/**
 * @author paul
 * @version $Id: SecurityService.java,v 1.98 2013/09/14 16:56:03 paul Exp $
 */
@SuppressWarnings("unused")
public interface SecurityService {

    /**
     * This is defined in spring-security AuthenticationConfigBuilder, and can be set in the {@code <security:anonymous/>}
     * configuration of the {@code <security:http/>} namespace config
     */
    String ANONYMOUS = AuthorityConstants.ANONYMOUS_USER_NAME;

    /**
     * Add a given user to a group by name.
     */
    void addUserToGroup( String userName, String groupName );

    /**
     * Check if the given securables are private.
     *
     * @throws AuthorizationServiceException if the collection is empty, see comments in
     *                                       {@link AclEntryCollectionVoter AclCollectionEntryVoter}
     */
    @Secured({ "ACL_SECURABLE_COLLECTION_READ" })
    <T extends Securable> Map<T, Boolean> arePrivate( Collection<T> securables );

    /**
     * Check if the given securable are shared.
     *
     * @throws AuthorizationServiceException if the collection is empty, see comments in
     *                                       {@link AclEntryCollectionVoter AclCollectionEntryVoter}
     */
    @Secured({ "ACL_SECURABLE_COLLECTION_READ" })
    <T extends Securable> Map<T, Boolean> areShared( Collection<T> securables );

    /**
     * Pick private securables.
     *
     * @return the subset which are private, if any
     */
    <T extends Securable> Collection<T> choosePrivate( Collection<T> securables );

    /**
     * Pick public securables.
     *
     * @return the subset that are public, if any
     */
    <T extends Securable> Collection<T> choosePublic( Collection<T> securables );

    /**
     * If the group already exists, an exception will be thrown.
     */
    void createGroup( String groupName );

    /**
     * Retrieve a list of users allowed to edit a given securable.
     *
     * @return list of userNames who can edit the given securable.
     * @throws AuthorizationServiceException if the collection is empty, see comments in
     *                                       {@link AclEntryCollectionVoter AclCollectionEntryVoter}
     */
    @Secured({ "ACL_SECURABLE_READ" })
    Collection<String> editableBy( Securable s );

    /**
     * We make this available to anonymous
     */
    Integer getAuthenticatedUserCount();

    /**
     * @return user names
     */
    @Secured("GROUP_ADMIN")
    Collection<String> getAuthenticatedUserNames();

    /**
     * This methods is only available to administrators.
     *
     * @return collection of all available security ids (basically, user names and group authorities.
     */
    @Secured("GROUP_ADMIN")
    Collection<Sid> getAvailableSids();

    String getGroupAuthorityNameFromGroupName( String groupName );

    /**
     * @throws AuthorizationServiceException if the collection is empty, see comments in
     *                                       {@link AclEntryCollectionVoter AclCollectionEntryVoter}
     */
    @Secured({ "ACL_SECURABLE_COLLECTION_READ" })
    <T extends Securable> Map<T, Collection<String>> getGroupsEditableBy( Collection<T> securables );

    @Secured({ "ACL_SECURABLE_READ" })
    Collection<String> getGroupsEditableBy( Securable s );

    @Secured({ "ACL_SECURABLE_COLLECTION_READ" })
    <T extends Securable> Map<T, Collection<String>> getGroupsReadableBy( Collection<T> securables );

    /**
     * @return names of groups which have read access to the securable, limited to groups the current user can read.
     */
    @Secured({ "ACL_SECURABLE_READ" })
    Collection<String> getGroupsReadableBy( Securable s );

    Collection<String> getGroupsUserCanEdit( String userName );

    @Secured("ACL_SECURABLE_READ")
    Sid getOwner( Securable s );

    /**
     * Pretty much have to be either the owner of the securables or administrator to call this.
     *
     * @throws AccessDeniedException if the current user is not allowed to access the information.
     */
    @Secured("ACL_SECURABLE_COLLECTION_READ")
    <T extends Securable> Map<T, Sid> getOwners( Collection<T> securables );

    /**
     * @return true if the current user can edit the securable
     */
    @Secured("ACL_SECURABLE_READ")
    boolean isEditable( Securable s );

    @Secured("ACL_SECURABLE_READ")
    boolean isEditableByGroup( Securable s, String groupName );

    /**
     * @return true if the user has WRITE permissions or ADMIN
     */
    @Secured("ACL_SECURABLE_READ")
    boolean isEditableByUser( Securable s, String userName );

    /**
     * @return true if the owner is the same as the current authenticated user. Special case: if the owner is an
     * administrator, and the uc
     */
    boolean isOwnedByCurrentUser( Securable s );

    /**
     * Convenience method to determine the visibility of an object.
     *
     * @return true if anonymous users can view (READ) the object, false otherwise. If the object doesn't have an ACL,
     * return true (be safe!)
     * @see org.springframework.security.acls.jdbc.BasicLookupStrategy
     */
    boolean isPrivate( Securable s );

    /**
     * Convenience method to determine the visibility of an object.
     *
     * @return the negation of isPrivate().
     */
    boolean isPublic( Securable s );

    @Secured("ACL_SECURABLE_READ")
    boolean isReadableByGroup( Securable s, String groupName );

    boolean isShared( Securable s );

    /**
     * @return true if the given user can read the securable, false otherwise. (READ or ADMINISTRATION required)
     */
    @Secured({ "ACL_SECURABLE_READ" })
    boolean isViewableByUser( Securable s, String userName );

    /**
     * Administrative method to allow a user to get access to an object. This is useful for cases where a data set is
     * loaded by admin but we need to hand it off to a user. If the user is the same as the current owner nothing is
     * done.
     * <p>
     * TODO: consider allowing a groupauthority to be the owner (GROUP_ADMIN) - see bug 2996
     */
    @Secured("GROUP_ADMIN")
    void makeOwnedByUser( Securable s, String userName );

    /**
     * Make a collection of objects private.
     */
    void makePrivate( Collection<? extends Securable> objs );

    /**
     * Makes the object private.
     */
    @Secured("ACL_SECURABLE_EDIT")
    void makePrivate( Securable object );

    /**
     * Make a collection of objects public.
     */
    void makePublic( Collection<? extends Securable> objs );

    /**
     * Makes the object public
     */
    @Secured("ACL_SECURABLE_EDIT")
    void makePublic( Securable object );

    /**
     * Adds read permission for a given group.
     */
    @Secured("ACL_SECURABLE_EDIT")
    void makeReadableByGroup( Securable s, String groupName ) throws AccessDeniedException;

    /**
     * Remove read permissions; also removes write permissions.
     *
     * @param groupName, with or without GROUP_
     */
    @Secured("ACL_SECURABLE_EDIT")
    void makeUnreadableByGroup( Securable s, String groupName ) throws AccessDeniedException;

    /**
     * Remove write permissions. Leaves read permissions, if present.
     */
    @Secured("ACL_SECURABLE_EDIT")
    void makeUnwriteableByGroup( Securable s, String groupName ) throws AccessDeniedException;

    /**
     * Adds write (and read) permissions.
     */
    @Secured("ACL_SECURABLE_EDIT")
    void makeWriteableByGroup( Securable s, String groupName ) throws AccessDeniedException;

    /**
     * @return list of userNames of users who can read the given securable.
     */
    @Secured("ACL_SECURABLE_EDIT")
    Collection<String> readableBy( Securable s );

    void removeUserFromGroup( String userName, String groupName );

    /**
     * Change the 'owner' of an object to a specific user. Note that this doesn't support making the owner a
     * grantedAuthority.
     */
    @Secured("GROUP_ADMIN")
    void setOwner( Securable s, String userName );
}